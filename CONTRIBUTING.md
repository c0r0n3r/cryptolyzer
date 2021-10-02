# Submitting bugs

## Due diligence

Before submitting a bug, please do the following:

- Perform **basic troubleshooting** steps:
  - **Make sure you\'re on the latest version.** If you\'re not on the most recent version, your problem may have been
    solved already! Upgrading is always the best first step.
  - **Try older versions.** If you\'re already *on* the latest release, try rolling back a few minor versions (e.g. if
    on 1.7, try 1.5 or 1.6) and see if the problem goes away. This will help the devs narrow down when the problem
    first arose in the commit log.
  - **Try switching up dependency versions.** If the software in question has dependencies (other libraries, etc) try
    upgrading/downgrading those as well.
- **Search the project\'s bug/issue tracker** to make sure it\'s not a known issue.
- If you don\'t find a pre-existing issue, consider **checking with the mailing list and/or IRC channel** in case the
  problem is non-bug-related.

## What to put in your bug report

Make sure your report gets the attention it deserves: bug reports with missing information may be ignored or punted back
to you, delaying a fix. The below constitutes a bare minimum; more info is almost always better:

- **What version of the core programming language interpreter/compiler are you using?** For example, if it\'s a Python
  project, are you using Python 2.7.3? Python 3.3.1? PyPy 2.0?
- **What operating system are you on?** Windows? (Vista? 7? 32-bit? 64-bit?) Mac OS X? (10.7.4? 10.9.0?) Linux? (Which
  distro? Which version of that distro? 32 or 64 bits?) Again, more detail is better.
- **Which version or versions of the software are you using?** Ideally, you followed the advice above and have ruled out
  (or verified that the problem exists in) a few different versions.
- **How can the developers recreate the bug on their end?** If possible, include a copy of your code, the command you
  used to invoke it, and the full output of your run (if applicable.)
  - A common tactic is to pare down your code until a simple (but still bug-causing) \"base case\" remains. Not only
    can this help you identify problems which aren\'t real bugs, but it means the developer can get to fixing the bug
    faster.

# Contributing changes

## Licensing of contributed material

Keep in mind as you contribute, that code, docs and other material submitted to open source projects are usually
considered licensed under the same terms as the rest of the work.

The details vary from project to project, but from the perspective of this document\'s authors:

- Anything submitted to a project falls under the licensing terms in the repository\'s top level `LICENSE` file.
  - For example, if a project\'s `LICENSE` is BSD-based, contributors should be comfortable with their work
    potentially being distributed in binary form without the original source code.
- Per-file copyright/license headers are typically extraneous and undesirable. Please don\'t add your own copyright
  headers to new files unless the project\'s license actually requires them!
  - Not least because even a new file created by one individual (who often feels compelled to put their personal
    copyright notice at the top) will inherently end up contributed to by dozens of others over time, making a
    per-file header outdated/misleading.

## Version control branching

- Always **make a new branch** for your work, no matter how small. This makes it easy for others to take just that one
  set of changes from your repository, in case you have multiple unrelated changes floating around.
  - A corollary: **don\'t submit unrelated changes in the same branch/pull request**! The maintainer shouldn\'t have
    to reject your awesome bugfix because the feature you put in with it needs more review.
- **Base your new branch off of the appropriate branch** on the main repository:
  - **Bug fixes** should be based on the branch named after the **oldest supported release line** the bug affects.
    - E.g. if a feature was introduced in 1.1, the latest release line is 1.3, and a bug is found in that feature -
      make your branch based on 1.1. The maintainer will then forward-port it to 1.3 and master.
    - Bug fixes requiring large changes to the code or which have a chance of being otherwise disruptive, may need
      to base off of **master** instead. This is a judgement call \-- ask the devs!
  - **New features** should branch off of **the \'master\' branch**.
    - Note that depending on how long it takes for the dev team to merge your patch, the copy of `master` you worked
      off of may get out of date! If you find yourself \'bumping\' a pull request that\'s been sidelined for a
      while, **make sure you rebase or merge to latest master** to ensure a speedier resolution.

## Code formatting

- **Follow the style you see used in the primary repository**! Consistency with the rest of the project always trumps
  other considerations. It doesn\'t matter if you have your own style or if the rest of the code breaks with the greater
  community - just follow along.
- Python projects usually follow the [PEP-8](http://www.python.org/dev/peps/pep-0008/) guidelines (though many have
  minor deviations depending on the lead maintainers\' preferences.)

## Tests aren\'t optional

Any bugfix that doesn\'t include a test proving the existence of the bug being fixed, may be suspect. Ditto for new
features that can\'t prove they actually work.

We\'ve found that test-first development really helps make features better architected and identifies potential edge
cases earlier instead of later. Writing tests before the implementation is strongly encouraged.
