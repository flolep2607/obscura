// Original wrappers keep their creation-realm prototype. Only adopted nodes
// dispatch native members through their current owner's captured implementations.
const _adoptedNodeRoutes = new WeakMap();
const _nodeNativeMembers = new Map();
// Retain dispatch intrinsics before page scripts can replace them.
const _nodeDispatchApply = Reflect.apply;
const _adoptedNodeRouteGet = _adoptedNodeRoutes.get.bind(_adoptedNodeRoutes);
const _adoptedNodeRouteSet = _adoptedNodeRoutes.set.bind(_adoptedNodeRoutes);
const _nodeNativeMemberGet = _nodeNativeMembers.get.bind(_nodeNativeMembers);
let _hasAdoptedNodeRoutes = false;

function _nodeNativeFrame(node) {
  const route = _adoptedNodeRouteGet(node);
  if (route) return __obscuraCore.ops.op_node_owner_frame(node);
  if (_cache.get(node._nid) === node) return _realmFrameId;
  return __obscuraCore.ops.op_node_owner_frame(node);
}
function _sameNativeTree(left, right) {
  if (_cache.get(left._nid) === left && _cache.get(right._nid) === right) return true;
  const owner = _nodeNativeFrame(left);
  return owner >= 0 && owner === _nodeNativeFrame(right);
}
function _adoptionPlan(node) {
  const result = JSON.parse(__obscuraCore.ops.op_adoption_nodes(node, node._nid >>> 0, _realmFrameId));
  if (result.error) throw new DOMException('The subtree cannot be adopted into this document.', result.error);
  return result.nodes;
}
function _adoptForInsertion(parent, node) {
  if (!_sameNativeTree(parent, node)) _adoptAcrossDocuments(_nodeDocumentForInsertion(parent), node);
}

function _registerNodeObserver(observer) {
  if (!globalThis.__mutationObservers.includes(observer)) globalThis.__mutationObservers.push(observer);
  if (!observer._nodeRegistries) observer._nodeRegistries = new Set();
  observer._nodeRegistries.add(globalThis.__mutationObservers);
}
function _observeNodeOwner(observer, node) {
  _registerNodeObserver(observer);
  if (_nodeNativeFrame(node) === _realmFrameId) return;
  const register = __obscuraCore.ops.op_node_owner_member(node, 'registerNodeObserver');
  if (!register) throw new DOMException('The observed document is no longer available.', 'InvalidStateError');
  _nodeDispatchApply(register, null, [observer]);
}
function _disconnectNodeObservers(observer) {
  for (const registry of observer._nodeRegistries || []) {
    const index = registry.indexOf(observer);
    if (index >= 0) registry.splice(index, 1);
  }
  observer._nodeRegistries?.clear();
}

function _nodeAdoptionSource(ids) {
  const root = this;
  const nodes = [];
  for (const nid of ids) {
    let node = _cache.get(nid);
    const type = +_dom('node_type', nid);
    if (!node) {
      // Native template contents use a document node but expose a fragment.
      node = type === 9 ? new DocumentFragment(nid) : _wrap(nid);
      _cache.set(nid, node);
    }
    if (!node || node._nid !== nid || !Object.isExtensible(node)) {
      throw new DOMException('The node wrapper cannot transfer ownership.', 'NotSupportedError');
    }
    const id = Object.getOwnPropertyDescriptor(node, '_nid');
    if (!id || !id.writable || !('value' in id)) {
      throw new DOMException('The node wrapper cannot transfer ownership.', 'NotSupportedError');
    }
    if (type === 1) _shadowRootForHost(node, true);
    nodes.push(node);
  }
  const parent = root.parentNode;
  const previous = root.previousSibling, next = root.nextSibling;
  const windowNames = _windowNamedNamesInTree(root);
  const moved = new Set(nodes);
  const observers = globalThis.__mutationObservers.filter(observer =>
    observer._targets.some(registration => moved.has(registration.target)));
  const records = nodes.map(node => ({ node, oldId: node._nid,
    route: _adoptedNodeRouteGet(node) || {},
    listeners: _eventTargetListeners.get(node),
    listenerChanged: _eventTargetListenerChanged.get(node),
    style: _elementStyleGet(node),
  }));
  return {
    bindings: nodes.map(node => [node, node._nid]),
    finish(mapping, target, document) {
      // Native commit has already detached the source. Clean source registries
      // with the old IDs before the wrappers receive their destination IDs.
      for (const record of records) {
        _detachStyleSheet(record.node);
        _detachLinkedStyleSheet(record.node);
        _cache.delete(record.oldId);
        _adoptedNodeRouteSet(record.node, record.route);
      }
      _hasAdoptedNodeRoutes = true;
      _treeMutationEpoch++; _domMutationEpoch++;
      target.install(records, mapping, root, document);
      for (const observer of observers) {
        target.registerObserver(observer);
        if (!observer._targets.some(registration => _nodeNativeFrame(registration.target) === _realmFrameId)) {
          const index = globalThis.__mutationObservers.indexOf(observer);
          if (index >= 0) globalThis.__mutationObservers.splice(index, 1);
          observer._nodeRegistries?.delete(globalThis.__mutationObservers);
        }
      }
      _reconcileWindowNamedProperties(windowNames);
      if (parent && _hasMutationObservers()) {
        _queueTreeMutationRecord(parent, [], [root], previous, next);
      }
    },
  };
}

const _nodeAdoptionTarget = Object.freeze({
  invoke(key, node, args) {
    const member = _nodeNativeMemberGet(key);
    if (!member) throw new DOMException('The native node operation is unavailable.', 'InvalidStateError');
    return _nodeDispatchApply(member, node, args);
  },
  registerObserver: _registerNodeObserver,
  install(records, mapping, root, document) {
    _treeMutationEpoch++; _domMutationEpoch++;
    _hasAdoptedNodeRoutes = true;
    for (let index = 0; index < mapping.length; index++) {
      const record = records[index], node = record.node;
      node._nid = mapping[index][1];
      node._treeDetachedExact = node === root;
      node._treeParentEpoch = -1;
      node._treeConnectedEpoch = -1;
      node._nodeDocument = undefined;
      record.route.frame = _realmFrameId;
      record.route.invoke = _nodeAdoptionTarget.invoke;
      _adoptedNodeRouteSet(node, record.route);
      _cache.set(node._nid, node);
      if (record.listeners) _eventTargetListeners.set(node, record.listeners);
      if (record.listenerChanged) _eventTargetListenerChanged.set(node, record.listenerChanged);
      if (record.style) _elementStyleSet(node, record.style);
      // Removal ends a style element's old CSSStyleSheet. Reconnection builds
      // the destination sheet from its content, as for same-document moves.
      __obscuraCore.ops.op_cssom_stylesheet_clear(node._nid, _realmFrameId);
    }
    _stampNodeDocument(root, document);
  },
});

function _adoptAcrossDocuments(document, node) {
  const ids = _adoptionPlan(node);
  const prepare = __obscuraCore.ops.op_node_owner_member(node, 'nodeAdoptionSource');
  if (!prepare) throw new DOMException('The source document is no longer available.', 'InvalidStateError');
  const source = _nodeDispatchApply(prepare, node, [ids]);
  const result = JSON.parse(__obscuraCore.ops.op_adopt_node(node, node._nid >>> 0, _realmFrameId, source.bindings));
  if (result.error) throw new DOMException('The subtree cannot be adopted into this document.', result.error);
  source.finish(result.mapping, _nodeAdoptionTarget, document);
  return node;
}

function _installAdoptedNodeDispatch() {
  const seen = new Set();
  for (const name of Object.getOwnPropertyNames(globalThis).sort()) {
    const constructor = Object.getOwnPropertyDescriptor(globalThis, name)?.value;
    const prototype = typeof constructor === 'function' ? constructor.prototype : null;
    if (!prototype || seen.has(prototype)
        || prototype !== Node.prototype && !Node.prototype.isPrototypeOf(prototype)) continue;
    seen.add(prototype);
    for (const property of Reflect.ownKeys(prototype)) {
      if (property === 'constructor') continue;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
      for (const kind of ['value', 'get', 'set']) {
        const member = descriptor[kind];
        if (typeof member !== 'function') continue;
        const key = name + ':' + String(property) + ':' + kind;
        _nodeNativeMembers.set(key, member);
        descriptor[kind] = ({ invoke(...args) {
          const route = _hasAdoptedNodeRoutes && _adoptedNodeRouteGet(this);
          if (route) {
            if (__obscuraCore.ops.op_node_owner_frame(this) < 0) {
              throw new DOMException('The owning document is no longer available.', 'InvalidStateError');
            }
            if (route.frame !== _realmFrameId) return route.invoke(key, this, args);
          }
          return _nodeDispatchApply(member, this, args);
        } }).invoke;
        Object.defineProperties(descriptor[kind], {
          name: { value: member.name, configurable: true },
          length: { value: member.length, configurable: true },
        });
      }
      Object.defineProperty(prototype, property, descriptor);
    }
  }
}
