(function () {
    // Always set the cookie to signal JS is enabled (even if form fields are missing)
    try {
        document.cookie = "js_captcha=enabled; Max-Age=31536000; Path=/; SameSite=Lax";
    } catch (e) {}

    // Helper to ensure a hidden input exists in a given form
    function ensureHidden(form, id) {
        let el = form.querySelector('#' + id);
        if (!el) {
            el = document.createElement('input');
            el.type = 'hidden';
            el.name = id;
            el.id = id;
            form.appendChild(el);
        }
        return el;
    }

    const forms = Array.from(document.querySelectorAll('form'));
    if (forms.length === 0) return;

    // Shared behavior events buffer
    const events = [];
    document.addEventListener('mousemove', e => {
        events.push({x: e.clientX, y: e.clientY, t: Date.now()});
    });
    document.addEventListener('keydown', () => {
        events.push({key: true, t: Date.now()});
    });
    document.addEventListener('click', () => {
        events.push({click: true, t: Date.now()});
    });

    // Initialize and wire up each form
    forms.forEach(form => {
        const tsField = ensureHidden(form, 'ts');
        const jsToken = ensureHidden(form, 'js_token');
        const behaviorField = ensureHidden(form, 'behavior_data');

        tsField.value = Date.now().toString();
        jsToken.value = 'set_by_js';

        form.addEventListener('submit', () => {
            try {
                behaviorField.value = btoa(JSON.stringify(events.slice(0, 100)));
            } catch (err) {}
        });
    });
})();
