use obscura_js::runtime::ObscuraJsRuntime;
use serde_json::json;

fn runtime() -> ObscuraJsRuntime {
    let mut rt = ObscuraJsRuntime::new();
    rt.set_dom(obscura_dom::parse_html("<body><div id=d></div></body>"));
    rt.run_page_init();
    rt
}

#[test]
fn html_element_interfaces_exist() {
    let mut rt = runtime();
    let missing = rt
        .evaluate(
            r#"`HTMLElement HTMLAnchorElement HTMLAreaElement HTMLAudioElement HTMLBaseElement HTMLBodyElement
            HTMLBRElement HTMLButtonElement HTMLCanvasElement HTMLDataElement HTMLDataListElement HTMLDetailsElement
            HTMLDialogElement HTMLDirectoryElement HTMLDivElement HTMLDListElement HTMLEmbedElement HTMLFieldSetElement
            HTMLFontElement HTMLFormElement HTMLFrameElement HTMLFrameSetElement HTMLHeadElement HTMLHeadingElement
            HTMLHRElement HTMLHtmlElement HTMLIFrameElement HTMLImageElement HTMLInputElement HTMLLabelElement
            HTMLLegendElement HTMLLIElement HTMLLinkElement HTMLMapElement HTMLMarqueeElement HTMLMediaElement
            HTMLMenuElement HTMLMetaElement HTMLMeterElement HTMLModElement HTMLObjectElement HTMLOListElement
            HTMLOptGroupElement HTMLOptionElement HTMLOutputElement HTMLParagraphElement HTMLParamElement
            HTMLPictureElement HTMLPreElement HTMLProgressElement HTMLQuoteElement HTMLScriptElement
            HTMLSelectElement HTMLSlotElement HTMLSourceElement HTMLSpanElement HTMLStyleElement
            HTMLTableCaptionElement HTMLTableCellElement HTMLTableColElement HTMLTableElement HTMLTableRowElement
            HTMLTableSectionElement HTMLTemplateElement HTMLTextAreaElement HTMLTimeElement HTMLTitleElement
            HTMLTrackElement HTMLUListElement HTMLUnknownElement HTMLVideoElement`
            .split(/\s+/).filter(n => typeof globalThis[n] !== 'function')"#,
        )
        .unwrap();
    assert_eq!(missing, json!([]));
}

#[test]
fn event_handler_properties_are_configurable_accessors() {
    let mut rt = runtime();
    let bad = rt
        .evaluate(
            r#"(() => {
            const targets = {
              window: [globalThis, ['onclick', 'onerror', 'onmessage', 'onhashchange', 'onpopstate', 'onresize', 'onunload', 'onbeforeunload', 'onstorage', 'onpagehide', 'onunhandledrejection', 'onmessageerror', 'ondevicemotion']],
              Document: [Document.prototype, ['onclick', 'onreadystatechange', 'onvisibilitychange', 'onselectionchange', 'onfullscreenchange', 'oncopy', 'onpaste', 'onkeydown', 'onload']],
              HTMLElement: [HTMLElement.prototype, ['onclick', 'onload', 'onerror', 'onkeydown', 'oncopy', 'onpaste', 'onanimationstart', 'ontransitionend', 'ontoggle', 'onfocus', 'onbeforecopy']],
              XMLHttpRequestEventTarget: [XMLHttpRequestEventTarget.prototype, ['onloadstart', 'onprogress', 'onabort', 'onerror', 'onload', 'ontimeout', 'onloadend']],
              XMLHttpRequest: [XMLHttpRequest.prototype, ['onreadystatechange']],
              FileReader: [FileReader.prototype, ['onloadstart', 'onprogress', 'onload', 'onabort', 'onerror', 'onloadend']],
              WebSocket: [WebSocket.prototype, ['onopen', 'onerror', 'onclose', 'onmessage']],
              EventSource: [EventSource.prototype, ['onopen', 'onerror', 'onmessage']],
              Worker: [Worker.prototype, ['onerror', 'onmessage', 'onmessageerror']],
            };
            const bad = [];
            for (const [k, [o, names]] of Object.entries(targets)) {
              for (const n of names) {
                const d = Object.getOwnPropertyDescriptor(o, n);
                if (!d || typeof d.get !== 'function' || typeof d.set !== 'function' || !d.configurable) bad.push(k + '.' + n);
              }
            }
            return bad;
            })()"#,
        )
        .unwrap();
    assert_eq!(bad, json!([]));
}

#[test]
fn event_handler_setters_store_functions_and_fire_once() {
    let mut rt = runtime();
    let out = rt
        .evaluate(
            r#"(() => {
            const el = document.getElementById('d');
            let calls = 0;
            const fn = () => { calls++; };
            const initial = [el.onclick, document.onclick, typeof window.onresize];
            el.onclick = fn;
            el.dispatchEvent(new Event('click'));
            const set = el.onclick === fn;
            el.onclick = 5;
            const cleared = el.onclick;
            const other = document.getElementById('d').ownerDocument.createElement('div').onclick;
            window.onresize = fn;
            return [initial, set, calls, cleared, other, window.onresize === fn, window.onerror];
            })()"#,
        )
        .unwrap();
    assert_eq!(out, json!([[null, null, "object"], true, 1, null, null, true, null]));
}

#[test]
fn xhr_constructor_leaves_handlers_to_the_prototype() {
    let mut rt = runtime();
    let out = rt
        .evaluate(
            r#"(() => {
            const x = new XMLHttpRequest();
            const own = Object.getOwnPropertyNames(x).filter(n => n.startsWith('on'));
            const f = () => {};
            x.onreadystatechange = f; x.onload = f;
            return [own, x.onreadystatechange === f, x.onload === f, x.onerror];
            })()"#,
        )
        .unwrap();
    assert_eq!(out, json!([[], true, true, null]));
}

// zone.js 0.8 (still shipped by older Angular apps): canPatchViaPropertyDescriptor installs a
// getter-only onreadystatechange on XMLHttpRequest.prototype and constructs an XHR, then
// patchProperty replaces every on* accessor it finds with one that also registers a listener.
// Its getter calls this.removeAttribute when the original getter is truthy, so the engine must
// not read handlers through the public property, and must fire a handler only once.
#[test]
fn zone_08_property_patching_boots() {
    let mut rt = runtime();
    let out = rt
        .evaluate(
            r#"(() => {
            'use strict';
            const proto = XMLHttpRequest.prototype;
            Object.defineProperty(proto, 'onreadystatechange', { get() { return true; } });
            const probe = !!new XMLHttpRequest().onreadystatechange;
            Object.defineProperty(proto, 'onreadystatechange', {});
            function patch(t, n) {
              const e = Object.getOwnPropertyDescriptor(t, n) || { enumerable: true, configurable: true };
              if (!Object.getOwnPropertyDescriptor(t, 'original' + n) && e.get) {
                Object.defineProperty(t, 'original' + n, { enumerable: false, configurable: true, get: e.get });
              }
              delete e.writable; delete e.value;
              const type = n.substr(2), key = '_' + n;
              e.set = function (v) {
                if (this[key]) this.removeEventListener(type, this[key]);
                if (typeof v === 'function') {
                  const w = function (ev) { const r = v.apply(this, arguments); if (r !== undefined && !r) ev.preventDefault(); };
                  this[key] = w; this.addEventListener(type, w, false);
                } else this[key] = null;
              };
              e.get = function () {
                let r = this[key] || null;
                if (r === null) {
                  const o = Object.getOwnPropertyDescriptor(t, 'original' + n);
                  if (o && o.get) { r = o.get.apply(this, arguments); if (r) { e.set.apply(this, [r]); this.removeAttribute(n); } }
                }
                return this[key] || null;
              };
              Object.defineProperty(t, n, e);
            }
            const patchAll = (t) => { for (const n in t) if (n.substr(0, 2) === 'on') patch(t, n); };
            patchAll(proto);
            patchAll(WebSocket.prototype);
            patchAll(FileReader.prototype);
            patch(HTMLElement.prototype, 'onclick');
            patch(globalThis, 'onerror');
            patch(Document.prototype, 'onreadystatechange');
            const x = new XMLHttpRequest();
            const calls = [];
            x.onreadystatechange = () => calls.push('rsc');
            x.onload = () => calls.push('load');
            x.open('GET', 'http://example.invalid/');
            x.dispatchEvent(new Event('load'));
            return [probe, calls.sort(), window.onerror, document.onreadystatechange, typeof HTMLFrameSetElement.prototype];
            })()"#,
        )
        .unwrap();
    assert_eq!(out, json!([true, ["load", "rsc"], null, null, "object"]));
}
