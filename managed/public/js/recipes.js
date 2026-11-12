// Starting points for common recurring assignments. A recipe only fills the
// workflow form: the operator chooses the worker, reads every field and
// creates the workflow paused or enabled, as for a blank one. Recipes make no
// claim about what an agent will do; they are instructions to adapt.

const WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri'];

export const RECIPES = [
  {
    id: 'dependency-audit',
    name: 'Weekly dependency audit',
    summary: 'Update dependencies one at a time, run the checks after each, and hold back what fails.',
    instructions: [
      '- Check every dependency of this repository for new releases and security advisories.',
      '- Apply patch and minor updates one at a time, and run the project\'s tests and linters after each.',
      '- Hold back anything that fails or needs a migration, and say why.',
      '- Report what changed, what was held back, and the exact commands you ran with their results.'
    ].join('\n'),
    schedule: { days: ['mon'], times: ['06:00'] },
    review: 'operator',
    reviewCriteria: 'Every updated and held-back package is listed with its old and new version, and every check is reported with its command and result.',
    maxRunsPerDay: 2,
    acceptanceMinutes: 60
  },
  {
    id: 'changelog-draft',
    name: 'Changelog draft',
    summary: 'Draft the next release\'s changelog from the pull requests merged since the last tag.',
    instructions: 'Read the commits merged since the last tag and draft the changelog section for the next release: user-visible changes first, then fixes, then internal work. Link each entry to its pull request. Report the draft and anything you could not classify.',
    schedule: { days: ['mon'], times: ['09:00'] },
    review: 'operator',
    reviewCriteria: 'Every merged pull request appears exactly once, under the right heading, with its number. Nothing is invented.',
    maxRunsPerDay: 2,
    acceptanceMinutes: 60
  },
  {
    id: 'flaky-tests',
    name: 'Flaky test triage',
    summary: 'Run the test suite several times and diagnose every test that both passed and failed.',
    instructions: 'Run the test suite five times. For every test that both passed and failed, open the test, find the source of nondeterminism, and propose a fix as a patch. Report each flaky test with its failure rate and your diagnosis. Do not change tests that passed every time.',
    schedule: { days: WEEKDAYS, times: ['02:00'] },
    review: 'operator',
    reviewCriteria: 'Each test reported as flaky has at least one passing and one failing run, its failure rate, and a diagnosis that names the source of nondeterminism.',
    maxRunsPerDay: 2,
    acceptanceMinutes: 120
  },
  {
    id: 'link-check',
    name: 'Documentation link check',
    summary: 'Find broken links in the documentation without editing anything.',
    instructions: 'Check every link in the README files and under docs/. For each broken link, report the file, the line, the link and the HTTP status or error. Do not edit any file. Report the number of links checked.',
    schedule: { days: ['fri'], times: ['16:00'] },
    review: 'none',
    reviewCriteria: null,
    maxRunsPerDay: 1,
    acceptanceMinutes: 60
  },
  {
    id: 'pricing-watch',
    name: 'Competitor pricing watch',
    summary: 'Compare public pricing pages with the previous snapshot and report every change with its source.',
    instructions: 'Visit the public pricing pages of the vendors listed in vendors.md. Record plan names, monthly and annual prices, and included usage. Compare with the previous snapshot in data/pricing/, and report every change with its source URL. Do not sign up for anything.',
    schedule: { days: WEEKDAYS, times: ['08:00', '16:00'] },
    review: 'operator',
    reviewCriteria: 'Every reported change has its source URL and both the old and the new value; unchanged vendors are counted, not described.',
    maxRunsPerDay: 4,
    acceptanceMinutes: 60
  },
  {
    id: 'issue-digest',
    name: 'Issue triage digest',
    summary: 'Summarize new and updated issues with a suggested label and priority, without changing them.',
    instructions: 'Read the issues opened or updated since the previous working day. For each, write one line: its number, a summary, a suggested label and a suggested priority with the reason. Flag anything that looks like a security report. Do not comment on, label or close any issue.',
    schedule: { days: WEEKDAYS, times: ['09:00'] },
    review: 'none',
    reviewCriteria: null,
    maxRunsPerDay: 1,
    acceptanceMinutes: 60
  }
];

/** The workflow form's starting values for a recipe, in the browser's own time zone. */
export function recipeTemplate(recipe) {
  return {
    name: recipe.name,
    instructions: recipe.instructions,
    intervalMinutes: null,
    schedule: { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, ...recipe.schedule },
    review: recipe.review,
    reviewerId: null,
    reviewCriteria: recipe.reviewCriteria,
    reworkLimit: 0,
    maxRunsPerDay: recipe.maxRunsPerDay,
    acceptanceMinutes: recipe.acceptanceMinutes
  };
}
