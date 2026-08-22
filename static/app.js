// Avatar dropdown (top-right, per wireframe: click avatar -> My Profile / Log Out)
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("avatarBtn");
  const dropdown = document.getElementById("avatarDropdown");
  if (btn && dropdown) {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      dropdown.classList.toggle("is-open");
    });
    document.addEventListener("click", () => dropdown.classList.remove("is-open"));
  }
});

// Generic tab wiring, used by any page with a `.tabs` container of id
// `containerId` holding `.tab[data-tab]` buttons and sibling
// `.tab-panel[data-panel]` sections.
function wireTabs(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.tab').forEach(b => b.classList.remove('is-active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('is-active'));
      btn.classList.add('is-active');
      const panel = document.querySelector(`.tab-panel[data-panel="${btn.dataset.tab}"]`);
      if (panel) panel.classList.add('is-active');
    });
  });
}

// Check In / Check Out buttons, used on both the employee dashboard and
// the profile page's "My Profile" card.
function wireCheckInOut() {
  const inBtn = document.getElementById("checkinBtn");
  const outBtn = document.getElementById("checkoutBtn");

  async function hit(url, btn) {
    if (!btn) return;
    btn.disabled = true;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "X-Requested-With": "fetch" },
      });
      const data = await res.json();
      if (data.ok) {
        window.location.reload();
      } else {
        btn.disabled = false;
        alert(data.error || "Something went wrong.");
      }
    } catch (err) {
      btn.disabled = false;
      alert("Network error — please try again.");
    }
  }

  if (inBtn) inBtn.addEventListener("click", () => hit("/attendance/checkin", inBtn));
  if (outBtn) outBtn.addEventListener("click", () => hit("/attendance/checkout", outBtn));
}
