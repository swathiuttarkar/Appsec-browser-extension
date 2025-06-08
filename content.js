console.log("[SecureView] Content script loaded.");

// === SCAN + DISPLAY ===
(function runSecurityScan() {
  console.log("[SecureView] Running security scan...");

  const issues = [];

  for (const rule of rules) {
    let result = rule.check(document);

    if (!Array.isArray(result)) {
      result = result ? [result] : [];
    }

    if (result.length > 0) {
      result.forEach(el => {
        if (el instanceof Element) {
          el.classList.add("secureview-highlight");
          el.setAttribute("data-secureview-tooltip", `${rule.description} (${rule.owasp})`);
        }
      });

      issues.push({
        id: rule.id,
        description: rule.description,
        owasp: rule.owasp,
        elements: result
      });
    }
  }

  console.log("[SecureView] Scan complete. Issues:", issues);

  // Show floating overlay panel with results
  renderOverlayPanel(issues);
})();

// === OVERLAY PANEL RENDER ===
function renderOverlayPanel(issues) {
  //if (!issues || issues.length === 0) return;

  const panel = document.createElement("div");
  panel.id = "secureview-panel";
  panel.style.position = "fixed";
  panel.style.bottom = "10px";
  panel.style.right = "10px";
  panel.style.width = "320px";
  panel.style.maxHeight = "300px";
  panel.style.overflowY = "auto";
  panel.style.backgroundColor = "#fff";
  panel.style.border = "1px solid #aaa";
  panel.style.padding = "10px";
  panel.style.boxShadow = "0 0 10px rgba(0,0,0,0.2)";
  panel.style.fontFamily = "sans-serif";
  panel.style.fontSize = "14px";
  panel.style.zIndex = "100000";

  if (!issues || issues.length === 0) 
    {panel.innerHTML = `
      <strong style="color: black;">🔒 SecureView Scanner </strong>
      <h1 style="color: black;"> No security issues found in this webpage </h1>
      <div>
      <button id="sv-hide-btn" style="
        margin-left: 260px;
        background:rgb(123, 240, 164);
        color: black;
        border: none;
        box-shadow: 1px 1px 4px rgb(97, 122, 107);
        border-radius: 4px;
        padding: 4px 8px;
        cursor: pointer;
        ">OK</button>
        </div>
      `;
      
    }
    else{
  panel.innerHTML = `
    <strong style="color: black;">🔒 SecureView Findings </strong>
    <div style="color: black;"> ${issues.length} issues found </div>
    <ul style="color: black;  padding: 4px 8px;">
      ${issues.map(i => `
        <li >
          <b>${i.id}</b><br>
          ${i.description}<br>
          <small><em>${i.owasp}</em></small>
        </li>
      `).join("")}
    </ul>
    
    <button id="sv-hide-btn" style="
    margin-left: 260px;
    background:rgb(150, 196, 249);
    color: black;
    border: none;
    box-shadow: 1px 1px 4px rgb(104, 117, 143);
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    ">Hide</button>
  `;
      }
  document.body.appendChild(panel);

  document.getElementById("sv-hide-btn").addEventListener("click", () => {
  panel.remove();
  document.querySelectorAll(".secureview-highlight").forEach(el =>
    el.classList.remove("secureview-highlight")
    );
  });

}

// === BASIC STYLE INJECTION FOR HIGHLIGHTS ===
const style = document.createElement("style");
style.textContent = `
  .secureview-highlight {
    outline: 2px solid red !important;
    position: relative;
  }
`;
document.head.appendChild(style);
