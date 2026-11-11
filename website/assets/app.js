/* zray site: language switch + copy buttons. No dependencies. */

(function () {
  var root = document.documentElement;
  var KEY = "zray-lang";

  function apply(lang) {
    root.setAttribute("data-lang", lang);
    root.setAttribute("lang", lang === "zh" ? "zh-CN" : "en");
    var buttons = document.querySelectorAll("[data-setlang]");
    for (var i = 0; i < buttons.length; i++) {
      var active = buttons[i].getAttribute("data-setlang") === lang;
      buttons[i].setAttribute("aria-pressed", active ? "true" : "false");
    }
    var defaultZh = "zray — 为老路由器写的 REALITY 客户端";
    var defaultEn = "zray — a REALITY client for routers";
    document.title =
      lang === "zh"
        ? (root.getAttribute("data-title-zh") || defaultZh)
        : (root.getAttribute("data-title-en") || defaultEn);
  }

  function initial() {
    var q = null;
    try {
      q = new URLSearchParams(location.search).get("lang");
    } catch (e) {}
    if (q === "zh" || q === "en") return q;
    var saved = null;
    try {
      saved = localStorage.getItem(KEY);
    } catch (e) {}
    if (saved === "zh" || saved === "en") return saved;
    var nav = navigator.language || navigator.userLanguage || "en";
    return nav.toLowerCase().indexOf("zh") === 0 ? "zh" : "en";
  }

  apply(initial());

  var switchers = document.querySelectorAll("[data-setlang]");
  for (var s = 0; s < switchers.length; s++) {
    switchers[s].addEventListener("click", function (ev) {
      var lang = ev.currentTarget.getAttribute("data-setlang");
      apply(lang);
      try {
        localStorage.setItem(KEY, lang);
      } catch (e) {}
    });
  }

  var copiers = document.querySelectorAll("[data-copy]");
  for (var c = 0; c < copiers.length; c++) {
    copiers[c].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var block = btn.closest(".code");
      var code = block ? block.querySelector("pre code") : null;
      if (!code) return;
      var text = code.innerText;
      var done = function () {
        var old = btn.innerHTML;
        btn.textContent = "✓";
        setTimeout(function () {
          btn.innerHTML = old;
        }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {});
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
          done();
        } catch (e) {}
        document.body.removeChild(ta);
      }
    });
  }
})();
