//! Cross-document adoption keeps native ownership separate from creation realm.
//! The commit invokes no JavaScript: all wrappers and owner records are checked
//! before the native subtree moves, then their hidden owner records move with it.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use deno_core::{op2, v8, OpState};
use obscura_dom::NodeId;
use crate::ops::{self, ObscuraState, RealmStates, SharedState};

#[derive(Clone, Copy)]
enum AdoptionError { InvalidState, Security, Unsupported, Hierarchy, Allocation }
impl AdoptionError {
    fn name(self) -> &'static str {
        match self {
            Self::InvalidState => "InvalidStateError", Self::Security => "SecurityError",
            Self::Unsupported => "NotSupportedError", Self::Hierarchy => "HierarchyRequestError",
            Self::Allocation => "QuotaExceededError",
        }
    }
    fn json(self) -> String { serde_json::json!({"error": self.name()}).to_string() }
}

fn owner_key<'s, 'i>(scope: &mut v8::PinScope<'s, 'i>) -> Option<v8::Local<'s, v8::Private>> {
    let name = v8::String::new(scope, "obscura.NodeOwner")?;
    Some(v8::Private::for_api(scope, Some(name)))
}

pub(crate) fn owner_context<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    state: &OpState,
    receiver: v8::Local<v8::Object>,
) -> Option<v8::Local<'s, v8::Context>> {
    let key = owner_key(scope)?;
    let binding = receiver.get_private(scope, key)?;
    let (context, generation) = if binding.is_undefined() {
        (receiver.get_creation_context(scope)?, None)
    } else {
        let binding = v8::Local::<v8::Array>::try_from(binding).ok()?;
        let global = binding.get_index(scope, 0)?.to_object(scope)?;
        let generation = binding.get_index(scope, 1)?.to_rust_string_lossy(scope).parse::<u64>().ok()?;
        (global.get_creation_context(scope)?, Some(generation))
    };
    let owner = context.get_embedder_data(scope, ops::DOCUMENT_OWNER_SLOT)?;
    if !owner.is_uint32() { return None; }
    let owner = owner.uint32_value(scope)?;
    let shared = ops::live_import_state(state, owner)?;
    if generation.is_some_and(|generation| shared.borrow().document_generation != generation) { return None; }
    if owner != 0 {
        let known = state.borrow::<Rc<RefCell<RealmStates>>>().borrow().context(owner)?;
        if known != context { return None; }
    }
    Some(context)
}

pub(crate) fn owner_frame(
    scope: &mut v8::PinScope,
    state: &OpState,
    receiver: v8::Local<v8::Object>,
) -> Option<u32> {
    let context = owner_context(scope, state, receiver)?;
    context.get_embedder_data(scope, ops::DOCUMENT_OWNER_SLOT)?.uint32_value(scope)
}

// The source helper is captured in its native context, never resolved through
// page-replaceable properties or the wrapper's original public prototype.
#[op2]
pub(crate) fn op_node_owner_member<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    state: &OpState,
    receiver: v8::Local<'s, v8::Object>,
    #[string] name: &str,
) -> v8::Local<'s, v8::Value> {
    let member = (|| {
        if !matches!(name, "nodeAdoptionSource" | "registerNodeObserver") { return None; }
        let context = owner_context(scope, state, receiver)?;
        let members = context.get_embedder_data(scope, ops::DOCUMENT_MEMBERS_SLOT)?.to_object(scope)?;
        let key = v8::String::new(scope, name)?;
        let member = members.get(scope, key.into())?;
        member.is_function().then_some(member)
    })();
    member.unwrap_or_else(|| v8::undefined(scope).into())
}

fn plan(
    state: &OpState, source_frame: u32, source_nid: NodeId, target_frame: u32,
) -> Result<(SharedState, SharedState, Vec<NodeId>), AdoptionError> {
    let source = ops::live_import_state(state, source_frame).ok_or(AdoptionError::InvalidState)?;
    let target = ops::live_import_state(state, target_frame).ok_or(AdoptionError::InvalidState)?;
    if Rc::ptr_eq(&source, &target) { return Err(AdoptionError::InvalidState); }
    let nodes = {
        let source_state = source.borrow();
        let target_state = target.borrow();
        let origin = ops::storage_origin(&source_state);
        if &*origin == "null" || &*origin != &*ops::storage_origin(&target_state) {
            return Err(AdoptionError::Security);
        }
        let dom = source_state.dom.as_ref().ok_or(AdoptionError::InvalidState)?;
        if dom.is_shadow_root(source_nid) { return Err(AdoptionError::Hierarchy); }
        if source_nid == dom.document() { return Err(AdoptionError::Unsupported); }
        let nodes = dom.adoption_node_ids(source_nid).map_err(|_| AdoptionError::InvalidState)?;
        // These elements own asynchronous or native resources in addition to
        // DOM state. Until those lifecycles can transfer, reject before either
        // arena changes instead of losing resources or targeting an old ID.
        for node in &nodes {
            if dom.get_node(*node).and_then(|node| node.as_element().map(|name| name.local.to_string()))
                .is_some_and(|tag| matches!(tag.as_str(), "iframe" | "frame" | "object" | "embed"
                    | "canvas" | "video" | "audio" | "img" | "link")) {
                return Err(AdoptionError::Unsupported);
            }
        }
        #[cfg(feature = "render")]
        if source_state.animation_timeline.waapi_nodes().iter().any(|node| nodes.contains(node)) {
            return Err(AdoptionError::Unsupported);
        }
        nodes
    };
    Ok((source, target, nodes))
}

#[op2]
#[string]
pub(crate) fn op_adoption_nodes(
    scope: &mut v8::PinScope, state: &OpState,
    receiver: v8::Local<v8::Object>, source_nid: u32, target_frame: u32,
) -> String {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let source_frame = owner_frame(scope, state, receiver).ok_or(AdoptionError::InvalidState)?;
        let (_, _, nodes) = plan(state, source_frame, NodeId::new(source_nid), target_frame)?;
        Ok::<_, AdoptionError>(serde_json::json!({"nodes": nodes.iter().map(|node| node.raw()).collect::<Vec<_>>()}))
    })).unwrap_or(Err(AdoptionError::InvalidState));
    match result { Ok(value) => value.to_string(), Err(error) => error.json() }
}

#[op2]
#[string]
pub(crate) fn op_adopt_node<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>, state: &OpState,
    receiver: v8::Local<'s, v8::Object>, source_nid: u32, target_frame: u32,
    bindings: v8::Local<'s, v8::Array>,
) -> String {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let source_frame = owner_frame(scope, state, receiver).ok_or(AdoptionError::InvalidState)?;
        let mut wrappers = Vec::new();
        let mut ids = Vec::new();
        for index in 0..bindings.length() {
            let binding = bindings.get_index(scope, index).ok_or(AdoptionError::InvalidState)?;
            let binding = v8::Local::<v8::Array>::try_from(binding).map_err(|_| AdoptionError::InvalidState)?;
            let wrapper = binding.get_index(scope, 0).and_then(|value| value.to_object(scope))
                .ok_or(AdoptionError::InvalidState)?;
            let id = binding.get_index(scope, 1).and_then(|value| value.uint32_value(scope))
                .ok_or(AdoptionError::InvalidState)?;
            if owner_frame(scope, state, wrapper) != Some(source_frame) { return Err(AdoptionError::InvalidState); }
            wrappers.push(wrapper); ids.push(NodeId::new(id));
        }
        if owner_frame(scope, state, receiver) != Some(source_frame)
            || wrappers.iter().any(|wrapper| owner_frame(scope, state, *wrapper) != Some(source_frame)) {
            return Err(AdoptionError::InvalidState);
        }
        // Repeat the plan after reading JS arrays. A getter cannot change the
        // source graph between preflight and this callback-free transaction.
        let (source, target, expected) = plan(state, source_frame, NodeId::new(source_nid), target_frame)?;
        if ids != expected || ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            return Err(AdoptionError::InvalidState);
        }
        let context = if target_frame == 0 {
            let context = scope.get_current_context();
            let id = context.get_embedder_data(scope, ops::DOCUMENT_OWNER_SLOT)
                .and_then(|value| value.uint32_value(scope));
            if id != Some(0) { return Err(AdoptionError::InvalidState); }
            context
        } else {
            let context = state.borrow::<Rc<RefCell<RealmStates>>>().borrow().context(target_frame)
                .ok_or(AdoptionError::InvalidState)?;
            v8::Local::new(scope, context)
        };
        let global = context.global(scope);
        let generation = v8::String::new(scope, &target.borrow().document_generation.to_string())
            .ok_or(AdoptionError::Allocation)?;
        let owner = v8::Array::new_with_elements(scope, &[global.into(), generation.into()]);
        let key = owner_key(scope).ok_or(AdoptionError::Allocation)?;
        for wrapper in &wrappers {
            let before = wrapper.get_private(scope, key).ok_or(AdoptionError::InvalidState)?;
            if !wrapper.set_private(scope, key, before).unwrap_or(false) { return Err(AdoptionError::InvalidState); }
        }
        let (root, mapping) = {
            let mut source = source.borrow_mut();
            let mut target = target.borrow_mut();
            let source_dom = source.dom.as_ref().ok_or(AdoptionError::InvalidState)?;
            let target_dom = target.dom.as_ref().ok_or(AdoptionError::InvalidState)?;
            let result = target_dom.adopt_node_from(source_dom, NodeId::new(source_nid))
                .map_err(|error| match error {
                    obscura_dom::tree::AdoptNodeError::Allocation => AdoptionError::Allocation,
                    _ => AdoptionError::InvalidState,
                })?;
            for (old, new) in &result.1 {
                if source.already_started_scripts.borrow_mut().remove(old) {
                    target.already_started_scripts.borrow_mut().insert(*new);
                }
                #[cfg(feature = "render")]
                if let Some(offset) = source.element_scroll_offsets.remove(old) {
                    target.element_scroll_offsets.insert(*new, offset);
                }
            }
            #[cfg(feature = "render")]
            source.animation_timeline.remove_subtree(ids.iter());
            retire_render_state(&mut source);
            retire_render_state(&mut target);
            result
        };
        for wrapper in wrappers {
            if !wrapper.set_private(scope, key, owner.into()).unwrap_or(false) {
                return Err(AdoptionError::InvalidState);
            }
        }
        Ok::<_, AdoptionError>(serde_json::json!({"nid":root.raw(), "mapping":mapping.iter()
            .map(|(old,new)| [old.raw(),new.raw()]).collect::<Vec<_>>()}))
    })).unwrap_or(Err(AdoptionError::InvalidState));
    match result { Ok(value) => value.to_string(), Err(error) => error.json() }
}

fn retire_render_state(state: &mut ObscuraState) {
    state.activity_generation = state.activity_generation.wrapping_add(1);
    *state.base_url_cache.borrow_mut() = None;
    #[cfg(feature = "render")]
    {
        state.prepared_render = None;
        state.pending_style_mutations.clear();
        state.style_query_cache = None;
        state.resolved_scroll = None;
    }
}
