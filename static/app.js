(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  // Жоюды растау
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // Іздеу
  const search = document.getElementById("search");
  if (search) {
    search.addEventListener("input", () => {
      const q = search.value.trim().toLowerCase();
      document.querySelectorAll("#list .row").forEach((r) => {
        r.hidden = q && !r.dataset.text.includes(q);
      });
    });
  }

  // Парольді көрсету / көшіру
  async function fetchPassword(id) {
    const res = await fetch("/reveal/" + id, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    });
    if (!res.ok) throw new Error("Қате");
    return (await res.json()).password;
  }

  document.querySelectorAll("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const out = document.querySelector('.pw[data-id="' + id + '"]');
      try {
        if (btn.dataset.act === "show") {
          if (out.dataset.shown) {
            out.textContent = "••••••••••";
            delete out.dataset.shown;
            btn.textContent = "Көрсету";
          } else {
            out.textContent = await fetchPassword(id);
            out.dataset.shown = "1";
            btn.textContent = "Жасыру";
            setTimeout(() => {
              out.textContent = "••••••••••";
              delete out.dataset.shown;
              btn.textContent = "Көрсету";
            }, 15000);
          }
        } else {
          await navigator.clipboard.writeText(await fetchPassword(id));
          const old = btn.textContent;
          btn.textContent = "Көшірілді";
          setTimeout(() => (btn.textContent = old), 1500);
          // 30 секундтан кейін буферді тазалау
          setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
        }
      } catch (e) {
        alert("Парольді алу мүмкін болмады. Қайта кіріп көріңіз.");
      }
    });
  });

  // Форма: парольді көрсету және генератор
  const pw = document.getElementById("pw");
  if (pw) {
    document.getElementById("toggle-pw").addEventListener("click", (e) => {
      const hidden = pw.type === "password";
      pw.type = hidden ? "text" : "password";
      e.target.textContent = hidden ? "Жасыру" : "Көрсету";
    });

    const box = document.getElementById("gen-box");
    const len = document.getElementById("len");
    const lenOut = document.getElementById("len-out");
    const sym = document.getElementById("sym");

    function generate() {
      let chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      if (sym.checked) chars += "!@#$%^&*-_=+?";
      const n = parseInt(len.value, 10);
      const limit = Math.floor(256 / chars.length) * chars.length;
      let out = "";
      const buf = new Uint8Array(1);
      while (out.length < n) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) out += chars[buf[0] % chars.length];
      }
      pw.value = out;
      pw.type = "text";
      document.getElementById("toggle-pw").textContent = "Жасыру";
    }

    document.getElementById("gen-pw").addEventListener("click", () => {
      box.hidden = false;
      generate();
    });
    len.addEventListener("input", () => {
      lenOut.textContent = len.value;
      generate();
    });
    sym.addEventListener("change", generate);
  }
})();
