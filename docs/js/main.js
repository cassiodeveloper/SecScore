const scoreEl = document.getElementById("score-number");
const pillEl = document.getElementById("decision-pill");

const targetScore = 82;
let currentScore = 0;

function getDecision(score) {
  if (score >= 85) {
    return { label: "PASS", color: "#47d18c", bg: "rgba(71,209,140,0.12)", border: "rgba(71,209,140,0.25)" };
  }

  if (score >= 51) {
    return { label: "REVIEW", color: "#ffb648", bg: "rgba(255,182,72,0.12)", border: "rgba(255,182,72,0.25)" };
  }

  return { label: "FAIL", color: "#ff5d73", bg: "rgba(255,93,115,0.12)", border: "rgba(255,93,115,0.25)" };
}

function animateScore() {
  const step = () => {
    currentScore += Math.ceil((targetScore - currentScore) / 8);

    if (currentScore >= targetScore) {
      currentScore = targetScore;
    }

    scoreEl.textContent = currentScore;

    const decision = getDecision(currentScore);
    pillEl.textContent = decision.label;
    pillEl.style.color = decision.color;
    pillEl.style.background = decision.bg;
    pillEl.style.borderColor = decision.border;

    if (currentScore < targetScore) {
      requestAnimationFrame(step);
    }
  };

  requestAnimationFrame(step);
}

function initReveal() {
  const items = document.querySelectorAll(".reveal");

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    {
      threshold: 0.14
    }
  );

  items.forEach((item) => observer.observe(item));
}

window.addEventListener("DOMContentLoaded", () => {
  animateScore();
  initReveal();
});