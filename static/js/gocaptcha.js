(function () {
    const tsField = document.getElementById('ts');
    const jsToken = document.getElementById('js_token');
    const behaviorField = document.getElementById('behavior_data');
    if (!tsField || !jsToken || !behaviorField) return;

    tsField.value = Date.now().toString();
    jsToken.value = "set_by_js";
    try {
        document.cookie = "js_captcha=enabled; Max-Age=31536000; Path=/; SameSite=Lax";
    } catch (e) {
    }

    const events = [];
    document.addEventListener('mousemove', e => {
        events.push({x: e.clientX, y: e.clientY, t: Date.now()});
    });
    document.addEventListener('keydown', e => {
        events.push({key: e.key, t: Date.now()});
    });
    document.addEventListener('click', e => {
        events.push({click: true, t: Date.now()});
    });
    document.querySelector('form').addEventListener('submit', e => {
        try {
            behaviorField.value = btoa(JSON.stringify(events.slice(0, 100)));
        } catch (err) {
        }
    });
})();
