import { useLayoutEffect, useRef } from 'react';

// Keyboard-operable tab list: arrows, Home and End move between modes (roving tabindex).
export default function Tabs({ tabs, value, onChange, label }) {
  const refs = useRef({});
  const list = useRef(null);
  // A sliding indicator under the selected tab: its position and width are CSS variables on the list.
  useLayoutEffect(() => {
    const place = () => {
      const tab = refs.current[value];
      if (!tab || !list.current) return;
      list.current.style.setProperty('--x', `${tab.offsetLeft}px`);
      list.current.style.setProperty('--w', `${tab.offsetWidth}px`);
    };
    place();
    document.fonts?.ready.then(place);
    window.addEventListener('resize', place);
    return () => window.removeEventListener('resize', place);
  }, [value]);
  const move = (event) => {
    const index = tabs.findIndex((tab) => tab.id === value);
    let next = null;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next === null) return;
    event.preventDefault();
    onChange(tabs[next].id);
    refs.current[tabs[next].id]?.focus();
  };

  return (
    <div role="tablist" aria-label={label} className="tabs" data-ui onKeyDown={move} ref={list}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          ref={(node) => {
            refs.current[tab.id] = node;
          }}
          role="tab"
          type="button"
          id={`tab-${tab.id}`}
          aria-selected={value === tab.id}
          aria-controls={`panel-${tab.id}`}
          tabIndex={value === tab.id ? 0 : -1}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
