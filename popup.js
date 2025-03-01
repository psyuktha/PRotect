import analyzeSecurityIssues from './gem.js';

document.addEventListener("DOMContentLoaded", () => {
  // Query active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];

    // Only analyze if we're on a GitHub PR page
    if (activeTab.url.match(/github\.com\/.*\/pull\//)) {
      chrome.tabs.sendMessage(
        activeTab.id,
        { action: "getDiff" },
        async (response) => {
          if (response && response.diff) {
            try {
              const securityIssues = await analyzeSecurityIssues(response.diff);
              console.log(securityIssues);
              updateUI(securityIssues);
            } catch (error) {
              console.error('Error analyzing security issues:', error);
              // Optionally update UI to show error
              updateUI({ error: 'Failed to analyze security issues' });
            }
          }
        }
      );
    } else {
      document.body.innerHTML =
        '<p class="error-message">Please open a GitHub pull request to analyze.</p>';
    }
  });
});

function updateUI(results) {
  const scoreElement = document.getElementById("security-score");
  const scoreCircle = document.querySelector(".score-circle");
  const issuesContainer = document.getElementById("issues-container");

  // Update score
  scoreElement.textContent = Math.round(results.score);

  // Update score circle color
  scoreCircle.className = "score-circle";
  if (results.score >= 80) {
    scoreCircle.classList.add("high");
  } else if (results.score >= 60) {
    scoreCircle.classList.add("medium");
  } else {
    scoreCircle.classList.add("low");
  }

  // Display files analyzed
  const filesAnalyzed = document.createElement("p");
  filesAnalyzed.className = "files-analyzed";
  filesAnalyzed.textContent = `Analyzed ${results.filesAnalyzed} file${
    results.filesAnalyzed !== 1 ? "s" : ""
  }`;
  issuesContainer.appendChild(filesAnalyzed);

  // Group issues by type
  const groupedIssues = results.issues.reduce((acc, issue) => {
    if (!acc[issue.type]) {
      acc[issue.type] = [];
    }
    acc[issue.type].push(issue);
    return acc;
  }, {});

  // Display issues grouped by type
  Object.entries(groupedIssues).forEach(([type, issues]) => {
    const groupElement = document.createElement("div");
    groupElement.className = "issue-group";

    const groupTitle = document.createElement("h3");
    groupTitle.className = "issue-group-title";
    groupTitle.textContent = `${type} (${issues.length})`;
    groupElement.appendChild(groupTitle);
    console.log(issues);
    issues.forEach((issue) => {
      const issueElement = document.createElement("div");
      issueElement.className = "issue-item";
      issueElement.innerHTML = `
        <div class="issue-title">${issue.message}</div>
        <p class="issue-file">File: ${issue.file}</p>
        <p class="issue-description">Found: ${issue.line}</p>
      `;
      groupElement.appendChild(issueElement);
    });

    issuesContainer.appendChild(groupElement);
  });
}
