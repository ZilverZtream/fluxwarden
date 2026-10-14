// The owner-lifecycle cases share one allocation registry and a two-owner budget, so they run
// in this one file, one after another, never beside each other in parallel workers.
import './cp006-guards.cases.js';
import './cp006-manifest.cases.js';
import './cp006-owner.cases.js';
import './cp006-readiness.cases.js';
import './cp008-credentials.cases.js';
