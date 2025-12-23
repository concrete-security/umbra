
export const EXAMPLE_THEMES = {  "medical-report": {
    id: "medical-report",
    dir: "medical-report",
    buttonLabel: "Summarize blood test results",
    prompt:
      "Based on these blood test results, highlight any values that fall outside the normal range and explain them briefly in non-medical terms.",
},
  "market-study": {
    id: "market-study",
    dir: "market-study",
    buttonLabel: "Summarize this market study",
    prompt:
      "Based on this market study, provide a very concise summary of the brand’s overall situation.",
  },
} as const

// The following prevents typos when indexing EXAMPLE_THEMES

// Allow only valid main keys from EXAMPLE_THEMES (eg: medical-report, market-study)
export type ExampleThemeId = keyof typeof EXAMPLE_THEMES

// Allow only valid keys after indexing EXAMPLE_THEMES[id] (eg: dir, buttonLabel, prompt)
export type ExampleTheme = (typeof EXAMPLE_THEMES)[ExampleThemeId]
