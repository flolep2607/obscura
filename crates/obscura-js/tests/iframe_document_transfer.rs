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
