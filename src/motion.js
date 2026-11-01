// Scroll entrances. An element marked data-reveal stays visible until the script has switched the page
// into motion mode (html.motion), so nothing is hidden if script fails or motion is reduced.
let observer;

export function enableMotion() {
  const reduced = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!reduced) document.documentElement.classList.add('motion');
}

// Ref callback: <section data-reveal ref={reveal}>. Adds data-in once, when the element enters the viewport.
export function reveal(node) {
  if (!node || node.hasAttribute('data-in')) return;
  if (typeof IntersectionObserver === 'undefined') {
    node.setAttribute('data-in', '');
    return;
  }
  observer ??= new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.setAttribute('data-in', '');
        observer.unobserve(entry.target);
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -5% 0px' },
  );
  observer.observe(node);
}
