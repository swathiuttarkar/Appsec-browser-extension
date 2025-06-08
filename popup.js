
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  chrome.scripting.executeScript({
    target: { tabId: tabs[0].id },
    func: () => window.__secureview_issues,
  }, function (results) {
    const issues = results[0]?.result || [];
    const container = document.getElementById("results");

    if (!issues || issues.length === 0) {
      container.innerText = "No issues found.";
      return;
    }

    container.innerHTML = `<ul>${issues.map(i =>
      `<li><b>${i.id}</b>: ${i.description} <br><small>${i.owasp}</small></li>`
    ).join("")}</ul>`;
  });
});
