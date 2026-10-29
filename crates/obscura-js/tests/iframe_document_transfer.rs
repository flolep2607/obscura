#![cfg(feature = "render")]

use obscura_dom::parse_html;
use obscura_js::runtime::ObscuraJsRuntime;
use serde_json::json;

async fn runtime_with_frame() -> ObscuraJsRuntime {
    let mut runtime = ObscuraJsRuntime::new();
    runtime.set_dom(parse_html(r#"<!doctype html><html><head>
        <style id="host-style" data-transfer="source">#target { width:47px; height:13px }</style>
        </head><body><p id="host-sentinel">parent</p></body></html>"#));
    runtime.set_url("https://iframe.example.invalid/");
    runtime.set_viewport(300.0, 200.0);
    runtime.run_page_init();
    runtime.execute_script("create-transfer-frame", r#"
        globalThis.frame = document.createElement('iframe');
        frame.srcdoc = '<!doctype html><html><head><style id="child-style">#target { width:23px; height:11px }</style></head><body><div id="target">child</div><p id="child-sentinel">untouched</p></body></html>';
        document.body.append(frame);
    "#).unwrap();
    runtime.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(runtime.evaluate(r#"(() => {
        const child = frame.contentDocument;
        const style = child.createElement('style');
        style.id = 'child-created';
        style.textContent = '#target { width:29px; height:17px }';
        child.head.append(style);
        const target = child.getElementById('target');
        const computed = frame.contentWindow.getComputedStyle(target);
        const result = [child.defaultView === frame.contentWindow,
            target instanceof frame.contentWindow.Element,
            style.ownerDocument === child, style.firstChild.ownerDocument === child,
            child.getElementById('child-created') === style,
            computed.width, computed.height, child.body.textContent];
        style.remove();
        return result;
    })()"#).expect("child-created styles must work before testing document transfer"),
        json!([true, true, true, true, true, "29px", "17px", "childuntouched"]));
    runtime
}

#[tokio::test(flavor = "current_thread")]
async fn cloned_host_style_is_adopted_when_appended_to_iframe() {
    let mut runtime = runtime_with_frame().await;
    let result = runtime.evaluate(r#"(() => {
        const child = frame.contentDocument;
        const source = document.getElementById('host-style');
        const original = source.outerHTML;
        const mirror = source.cloneNode(true);
        mirror.id = 'mirror';
        child.head.append(mirror);
        const computed = frame.contentWindow.getComputedStyle(child.getElementById('target'));
        return {
            identity: child.getElementById('mirror') === mirror,
            ownership: [mirror.ownerDocument === child, mirror.firstChild.ownerDocument === child],
            sourceUnchanged: source === document.getElementById('host-style') && source.outerHTML === original,
            hostMirror: document.getElementById('mirror') === null,
            attributes: mirror.getAttribute('data-transfer'),
            text: child.getElementById('mirror').textContent,
            styles: Array.from(child.head.querySelectorAll('style'), style => style.id),
            computed: [computed.width, computed.height],
            sentinels: [document.getElementById('host-sentinel').textContent,
                child.getElementById('child-sentinel').textContent, child.getElementById('target').textContent],
        };
    })()"#).expect("a host-cloned style must append into the iframe's native document");
    assert_eq!(result, json!({
        "identity": true,
        "ownership": [true, true],
        "sourceUnchanged": true,
        "hostMirror": true,
        "attributes": "source",
        "text": "#target { width:47px; height:13px }",
        "styles": ["child-style", "mirror"],
        "computed": ["47px", "13px"],
        "sentinels": ["parent", "untouched", "child"],
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn iframe_import_node_clones_into_destination_document() {
    let mut runtime = runtime_with_frame().await;
    let result = runtime.evaluate(r#"(() => {
        const child = frame.contentDocument;
        const source = document.getElementById('host-style');
        const original = source.outerHTML;
        const imported = child.importNode(source, true);
        const detached = [imported !== source, imported.parentNode === null,
            imported.ownerDocument === child, imported.firstChild.ownerDocument === child,
            imported instanceof frame.contentWindow.HTMLStyleElement];
        imported.id = 'imported';
        imported.textContent = '#target { width:61px; height:19px }';
        child.head.append(imported);
        const computed = frame.contentWindow.getComputedStyle(child.getElementById('target'));
        return {
            detached,
            identity: child.getElementById('imported') === imported,
            sourceUnchanged: source === document.getElementById('host-style') && source.outerHTML === original,
            hostImport: document.getElementById('imported') === null,
            attributes: imported.getAttribute('data-transfer'),
            text: child.getElementById('imported').textContent,
            computed: [computed.width, computed.height],
            sentinels: [document.getElementById('host-sentinel').textContent,
                child.getElementById('child-sentinel').textContent, child.getElementById('target').textContent],
        };
    })()"#).expect("importNode must create a deep copy in the iframe's native document");
    assert_eq!(result, json!({
        "detached": [true, true, true, true, true],
        "identity": true,
        "sourceUnchanged": true,
        "hostImport": true,
        "attributes": "source",
        "text": "#target { width:61px; height:19px }",
        "computed": ["61px", "19px"],
        "sentinels": ["parent", "untouched", "child"],
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn iframe_adopt_node_moves_descendants_and_preserves_listeners() {
    let mut runtime = runtime_with_frame().await;
    let result = runtime.evaluate(r#"(() => {
        const child = frame.contentDocument;
        const source = document.createElement('section');
        source.id = 'adopted';
        source.setAttribute('data-transfer', 'source');
        source.innerHTML = '<style>#target { width:73px; height:21px }</style><button>move</button><span id="leaf">kept</span>';
        document.body.append(source);
        const style = source.querySelector('style');
        const button = source.querySelector('button');
        const leaf = source.querySelector('span');
        const events = [];
        button.addEventListener('click', function(event) {
            events.push([this === button, event.target === button, button.ownerDocument === child]);
        });
        const adopted = child.adoptNode(source);
        const detached = [adopted === source, adopted.parentNode === null,
            document.getElementById('adopted') === null,
            adopted.ownerDocument === child, style.ownerDocument === child,
            style.firstChild.ownerDocument === child, button.ownerDocument === child,
            leaf.firstChild.ownerDocument === child];
        child.body.append(adopted);
        leaf.textContent = 'changed';
        button.dispatchEvent(new frame.contentWindow.Event('click'));
        const computed = frame.contentWindow.getComputedStyle(child.getElementById('target'));
        return {
            detached,
            identity: child.getElementById('adopted') === source && child.getElementById('leaf') === leaf,
            hostMoved: document.getElementById('adopted') === null && document.getElementById('leaf') === null,
            attributes: child.getElementById('adopted').getAttribute('data-transfer'),
            leaf: child.getElementById('leaf').textContent,
            computed: [computed.width, computed.height],
            events,
            sentinels: [document.getElementById('host-sentinel').textContent,
                child.getElementById('child-sentinel').textContent, child.getElementById('target').textContent],
        };
    })()"#).expect("adoptNode must move the native subtree while preserving JavaScript node identity");
    assert_eq!(result, json!({
        "detached": [true, true, true, true, true, true, true, true],
        "identity": true,
        "hostMoved": true,
        "attributes": "source",
        "leaf": "changed",
        "computed": ["73px", "21px"],
        "events": [[true, true, true]],
        "sentinels": ["parent", "untouched", "child"],
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_node_ids_cannot_mutate_an_unrelated_iframe_node() {
    let mut runtime = runtime_with_frame().await;
    let collision = runtime.evaluate_script(r#"(() => {
        const child = frame.contentDocument;
        const sources = Array.from({length:32}, () => document.createElement('span'));
        const targets = Array.from({length:32}, () => child.createElement('p'));
        const source = sources.find(source => targets.some(target => target._nid === source._nid));
        const target = targets.find(target => target._nid === source._nid);
        source.id = 'alias-source'; source.textContent = 'host';
        target.id = 'alias-target'; target.textContent = 'child';
        document.body.append(source); child.body.append(target);
        globalThis.aliasSource = source;
        globalThis.aliasTarget = target;
        globalThis.aliasFragment = document.createDocumentFragment();
        aliasFragment.append(document.createElement('span'));
        return source._nid === target._nid;
    })()"#).expect("fixture must find a real node-ID collision across native arenas");
    assert_eq!(collision, true);
    for (expression, fragment) in [
        ("box.appendChild(aliasSource)", false),
        ("box.insertBefore(aliasSource, aliasTarget)", false),
        ("box.replaceChild(aliasSource, aliasTarget)", false),
        ("box.append('prefix', aliasSource)", false),
        ("box.prepend(aliasSource)", false),
        ("box.appendChild(aliasFragment)", true),
        ("box.replaceChildren(aliasFragment)", true),
        ("box.replaceChildren('prefix', aliasSource)", false),
        ("aliasTarget.before(aliasSource)", false),
        ("aliasTarget.after(aliasSource)", false),
        ("aliasTarget.replaceWith(aliasSource)", false),
        ("frame.contentDocument.adoptNode(aliasSource)", false),
    ] {
        runtime.evaluate_script(r#"(() => {
            globalThis.box = frame.contentDocument.createElement('div');
            frame.contentDocument.body.append(box);
            box.append(aliasTarget);
            document.body.append(aliasSource);
            globalThis.fragmentLeaf = document.createElement('span');
            fragmentLeaf.textContent = 'fragment';
            globalThis.aliasFragment = document.createDocumentFragment();
            aliasFragment.append(fragmentLeaf);
        })()"#).unwrap();
        runtime.evaluate_script(expression).expect("cross-tree insertion must transfer ownership without aliasing");
        assert_eq!(runtime.evaluate_script(&format!(r#"(() => {{
            const moved = {moved};
            const child = frame.contentDocument;
            return [moved.ownerDocument === child, moved.textContent,
                aliasTarget.textContent, child.getElementById('child-sentinel').textContent,
                document.getElementById('host-sentinel').textContent,
                child.getElementById('target').textContent,
                moved !== aliasTarget, !moved.isSameNode(aliasTarget)];
        }})()"#, moved = if fragment { "fragmentLeaf" } else { "aliasSource" })).unwrap(),
            json!([true, if fragment { "fragment" } else { "host" }, "child", "untouched", "parent", "child", true, true]),
            "{expression}");
        runtime.evaluate_script("box.remove()").unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn iframe_import_preserves_form_template_and_started_script_state() {
    let mut runtime = runtime_with_frame().await;
    runtime.evaluate_script(r#"(() => {
        const source = document.createElement('section');
        source.innerHTML = '<input type="checkbox"><textarea>default</textarea><template><input value="default"></template>';
        source.querySelector('input').checked = true;
        source.querySelector('input').indeterminate = true;
        source.querySelector('textarea').value = 'dirty';
        source.querySelector('template').content.querySelector('input').value = 'template-dirty';
        const script = document.createElement('script');
        script.textContent = 'globalThis.transferScriptRuns = (globalThis.transferScriptRuns || 0) + 1';
        source.append(script); document.body.append(source);
        globalThis.stateSource = source;
        globalThis.stateImport = frame.contentDocument.importNode(source, true);
        globalThis.shallowImport = frame.contentDocument.importNode(source, false);
        frame.contentDocument.body.append(stateImport);
    })()"#).expect("cross-document import must preserve native cloning state");
    runtime.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(runtime.evaluate_script(r#"(() => {
        const child = frame.contentDocument;
        return [stateImport !== stateSource, stateImport.ownerDocument === child,
            stateImport.querySelector('input').checked,
            stateImport.querySelector('input').indeterminate,
            stateImport.querySelector('textarea').value,
            stateImport.querySelector('template').content.querySelector('input').value,
            shallowImport.ownerDocument === child, shallowImport.parentNode === null,
            shallowImport.childNodes.length,
            globalThis.transferScriptRuns, frame.contentWindow.transferScriptRuns || 0,
            stateSource.querySelector('input').indeterminate];
    })()"#).unwrap(), json!([true,true,true,false,"dirty","template-dirty",true,true,0,1,0,true]));
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_adoption_preserves_owned_state_and_observers_after_id_reuse() {
    let mut runtime = runtime_with_frame().await;
    runtime.evaluate_script(r#"(() => {
        const root = document.createElement('section');
        root.innerHTML = '<input type="checkbox"><template><input value="default"></template><div></div>';
        const input = root.querySelector('input');
        input.checked = true; input.indeterminate = true;
        const template = root.querySelector('template');
        const templateInput = template.content.querySelector('input');
        templateInput.value = 'dirty';
        const host = root.querySelector('div');
        const shadow = host.attachShadow({mode:'closed'});
        const shadowLeaf = document.createElement('span');
        shadowLeaf.textContent = 'shadow'; shadow.append(shadowLeaf);
        const style = input.style;
        style.width = '37px';
        const notices = [];
        const observer = new MutationObserver(records => notices.push(...records.map(record =>
            [record.type, record.target === input, record.attributeName])));
        observer.observe(input, {attributes:true});
        document.body.append(root);
        const oldIds = [root._nid, input._nid, template._nid, templateInput._nid, shadow._nid, shadowLeaf._nid];
        frame.contentDocument.body.append(root);
        const replacements = Array.from({length:40}, () => document.createElement('p'));
        for (const replacement of replacements) { replacement.textContent = 'source'; document.body.append(replacement); }
        const reused = replacements.some(node => oldIds.includes(node._nid));
        style.width = '41px'; input.setAttribute('data-moved', 'yes');
        const first = [root.ownerDocument === frame.contentDocument,
            root.querySelector('input') === input, input.checked, input.indeterminate,
            input.style === style, input.style.width, template.content.querySelector('input') === templateInput,
            templateInput.value, shadowLeaf.ownerDocument === frame.contentDocument, shadow.firstChild === shadowLeaf,
            replacements.every(node => node.textContent === 'source'), reused];
        document.body.append(root);
        frame.contentDocument.body.append(root);
        input.setAttribute('data-again', 'yes');
        globalThis.adoptionState = {root, input, templateInput, shadowLeaf, notices, observer, first};
    })()"#).expect("repeated adoption must preserve the entire owned subtree");
    runtime.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(runtime.evaluate_script(r#"(() => {
        const state = adoptionState;
        const result = [state.first, state.input.ownerDocument === frame.contentDocument,
            state.templateInput.value, state.shadowLeaf.textContent, state.notices];
        state.observer.disconnect();
        state.input.setAttribute('data-disconnected', 'yes');
        return result;
    })()"#).unwrap(), json!([
        [true,true,true,true,true,"41px",true,"dirty",true,true,true,true],
        true,"dirty","shadow",[["attributes",true,"style"],["attributes",true,"data-moved"],["attributes",true,"data-again"]]
    ]));
    runtime.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(runtime.evaluate_script("adoptionState.notices.length").unwrap().as_f64(), Some(3.0));
    runtime.evaluate_script(r#"(() => {
        globalThis.escapedNode = frame.contentDocument.createElement('p');
        escapedNode.textContent = 'escaped';
        document.body.append(escapedNode);
        frame.srcdoc = '<!doctype html><html><body><p id="fresh">new document</p></body></html>';
    })()"#).unwrap();
    runtime.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(runtime.evaluate_script(r#"(() => {
        escapedNode.textContent = 'still owned by parent';
        return [escapedNode.ownerDocument === document, escapedNode.parentNode === document.body,
            escapedNode.textContent, frame.contentDocument.getElementById('fresh').textContent];
    })()"#).expect("source-frame navigation must not invalidate a node now owned by the parent"),
        json!([true,true,"still owned by parent","new document"]));
    let error = runtime.evaluate_script("adoptionState.input.setAttribute('data-stale', 'yes')")
        .expect_err("a wrapper owned by the replaced destination document must fail closed");
    assert!(error.contains("InvalidStateError"), "{error}");
}

#[tokio::test(flavor = "current_thread")]
async fn unsupported_adoption_and_invalid_insertion_leave_source_intact() {
    let mut runtime = runtime_with_frame().await;
    runtime.evaluate_script(r#"(() => {
        globalThis.resourceRoot = document.createElement('section');
        resourceRoot.append(document.createElement('video'));
        document.body.append(resourceRoot);
        globalThis.ordinaryRoot = document.createElement('section');
        ordinaryRoot.textContent = 'kept'; document.body.append(ordinaryRoot);
    })()"#).unwrap();
    for (expression, error_name) in [
        ("frame.contentDocument.body.append(resourceRoot)", "NotSupportedError"),
        ("frame.contentDocument.adoptNode(resourceRoot)", "NotSupportedError"),
        ("frame.contentDocument.body.insertBefore(ordinaryRoot, document.body)", "NotFoundError"),
        ("frame.contentDocument.appendChild(ordinaryRoot)", "HierarchyRequestError"),
    ] {
        let error = runtime.evaluate_script(expression).expect_err("invalid transfer must fail before mutation");
        assert!(error.contains(error_name), "{expression}: {error}");
        assert_eq!(runtime.evaluate_script(r#"[resourceRoot.parentNode === document.body,
            resourceRoot.ownerDocument === document, resourceRoot.firstChild.localName,
            ordinaryRoot.parentNode === document.body, ordinaryRoot.textContent,
            frame.contentDocument.getElementById('child-sentinel').textContent]"#).unwrap(),
            json!([true,true,"video",true,"kept","untouched"]));
    }
}
