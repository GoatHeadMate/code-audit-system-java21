# Code Audit System Design

## 1. Product Role

Code Audit System is an operator-facing Java white-box audit console. The UI is dense, calm, and work-focused: it should help a reviewer scan jobs, inspect findings, and feed results back into the audit memory without feeling like a marketing page.

## 2. Palette

- Primary: Tailwind blue 600 (`bg-blue-600`, `text-blue-600`) for selected tabs, primary actions, and active job markers.
- Secondary: Tailwind indigo 500/600 for agent and attack-path accents.
- Success: Tailwind emerald 600/700 with emerald 50/200 surfaces for confirmed results and completed states.
- Warning: Tailwind amber/orange 500/600 with amber/orange 50/200 surfaces for review, downgrade, and high-risk warnings.
- Danger: Tailwind red 500/600 with red 50/200 surfaces for critical findings, failures, and false positives.
- Neutral: Tailwind slate scale for layout, borders, metadata, and quiet controls.

## 3. Typography

- System UI stack: `-apple-system`, BlinkMacSystemFont, Segoe UI, PingFang SC, Noto Sans SC.
- Mono stack: Consolas, Monaco, Menlo, Courier New for paths, rule IDs, logs, and code-like labels.
- Page text stays compact: 12-14px for operational controls, 14px for finding body text, small uppercase labels for section headers.

## 4. Spacing

- Base rhythm is 4px.
- Cards use 16-20px internal padding.
- Compact buttons use 4-8px vertical padding and 8-12px horizontal padding.
- Section gaps stay small (`gap-2`, `gap-3`, `mb-3`, `mb-4`) because the product is scan-heavy.

## 5. Components

- Job rows: left border marks selection; hover is a slate 50 tonal shift.
- Tabs: text button with a 2px blue underline when active.
- Finding cards: white surface, slate border, left severity stripe, subtle hover elevation.
- Feedback actions: small bordered buttons grouped at the bottom of a finding card. Automatic feedback should render as a status pill plus allow manual override actions.
- Rule candidate cards: white bordered cards with status pills and compact decision buttons.

## 6. States

- Loading and in-progress states use blue/emerald accents and short text.
- Errors use red text on quiet surfaces; avoid modal interruptions for recoverable actions.
- Completed machine actions should state whether they were written into audit memory.

## 7. Constraints

- Do not add decorative gradient sections, large hero layouts, or oversized card stacks.
- Keep all controls visible and compact on 768px and desktop widths.
- Preserve manual override for any automatic decision.
