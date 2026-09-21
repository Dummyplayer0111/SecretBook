# Explainable Django request detector

SecretBook is a research demo. The default is now a versioned component-scoring CNN
candidate in **monitor mode**: scores are computed and privacy-preserving events
are logged, but model positives do not block requests. Django's authentication,
CSRF and permissions still apply, as do WAF input bounds. The original character
CNN is preserved as the historical `legacy` pipeline.

The v3 candidate was selected using development data before a new synthetic Flaskr
test: 5/601 benign requests flagged (0.83%), 398/400 injected payloads detected
(99.50%). Reused source-test recall is 80.47%, including only 59.32% for CSIC
anomalies. The earlier v2 candidate's 25% Django-admin false-positive failure is
preserved and that dataset is now development evidence. These are limited research
results, not readiness to enable blocking. A subsequent frozen external ECML/PKDD
test of 50,116 requests produced **33.43% benign false positives** and 82.78%
attack-label recall; unseen-representation FPR was 40.29%. Neither model nor
threshold was changed after this failure. See ../EXTERNAL_ECML_RESULTS.md,
../REQUEST_V3_RESULTS.md and ../REQUEST_V2_RESULTS.md.

## Run

From this directory:

~~~powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
~~~

The current candidate and frozen selection are in ../artifacts/request_v3/.
WAF_CANDIDATE_DIR can point to a copied candidate directory when running outside
the full workspace. It needs selection.json and the selected artifact (plus
vocabulary.pkl for a CNN). Hashes are checked before loading. Historical model
files remain in models/; ../attack_model.pt and ../char_dict.pkl take precedence
only in legacy mode. No runtime scikit-learn dependency is required.
Configure SECRET_KEY, DEBUG and SMTP settings through the local environment/.env;
do not publish their values. ALLOWED_HOSTS defaults to local hosts.

Optional WAF settings:
- WAF_PIPELINE: `components` (default), `structured` (v2), or `legacy`.
- WAF_MODE: `monitor` (default) or `block`. Monitor forwards model positives.
- WAF_CANDIDATE_DIR: directory containing the frozen new candidate.
  For `structured`, explicitly point this to ../artifacts/request_v2/; versions
  are checked to prevent loading a model with the wrong input representation.
- WAF_CANDIDATE_THRESHOLD: optional candidate-only override; changes invalidate
  correspondence with reported frozen-threshold metrics.
- WAF_LOG_LEVEL: INFO by default; events omit payloads, routes and credential values.
- WAF_ATTACK_THRESHOLD: omitted/empty uses the checkpoint's selected threshold (0.45).
  This setting applies only to the legacy model.
- WAF_MAX_BODY_BYTES: default 16384.
- WAF_EXPLAIN_BLOCKS: default True.
- WAF_EXPOSE_DEBUG_HEADERS: default False; also requires DEBUG.

The selected artifact rejects mismatched preprocessing versions or vocabulary
hashes. Historical plain state-dictionary models are incompatible.

## Inspection behavior

Supported bodies are JSON, URL-encoded forms, plain text, XML and bounded multipart
text fields. Uploaded file contents are not classified. Bodies are read with a real
bound and restored for downstream Django access. Invalid framing returns 400,
oversized bodies/normalized text 413, oversized URLs 414 and unsupported nonempty
body types 415. Normalized inputs may contain at most 4096 characters.

The component pipeline has no route-specific exemptions. It scores payload values
with a common prefix across HTTP wrappers and takes the maximum CNN score across
all windows of all components. Ordinary route identifiers and relative-URL path
names become metadata; nested query/fragment payloads remain inspected. Named
structured password fields and valid CSRF tokens are omitted; username/payload
values remain visible. Malformed JSON is rejected explicitly. Excluded fields,
ordinary field names and route identities are outside detection scope. All admitted
requests, including navigation, are scored. The selected CNN can report character
sensitivity spans within its winning component; these do not prove an exploit.
The optional v2 linear model has no character-attribution spans.

In the optional legacy pipeline, known navigation paths, including built-in password change/reset pages, bypass
scoring for query-free GET/HEAD requests whose body has been verified empty.
Login navigation also accepts a single next value matching a configured safe path.
Password-reset confirmation navigation is recognized by its resolved Django view.
Bounded forms omit correctly formatted single CSRF tokens from model input.
Built-in login, password-change and password-reset-confirm forms omit their password
fields, and login omits a single conventional username. Credential-only POSTs go
directly to Django's authentication, password validation and CSRF checks. Additional
fields and other queries remain scored. Original form data are preserved. These
are explicit inspection exemptions, not improvements in model accuracy.
Scored blocks return HTML or JSON 403 with score, random reference and available
influential spans. A missing attribution is explicitly indicated. Spans describe
sensitivity of the model, not proof of an exploit. Logs omit raw paths and payloads.

Post deletion uses an authenticated POST form. Account deletion has a GET confirmation
page and a CSRF-protected POST action. Edits preserve creation time; feeds show newest
posts first.

## Verification and research artifacts

~~~powershell
python manage.py check
python manage.py test Post User -v 2
~~~

54 tests cover middleware, bounds, explanations, ownership and deletion behavior,
as well as successful login, password change/reset and authentication/CSRF checks,
including saved-model integration, v2/v3 authentication flows, component scoring
and explanation offsets. Tests use a separate in-memory database.

The research/ directory contains historical paper and measurement snapshots. The
current manuscript and v2/v3 reports are in the parent Project workspace. Raw
datasets, training scripts and complete runs also require that full workspace.

From the parent Project folder:

~~~powershell
.\SecretBook\venv\Scripts\python.exe benchmark_waf.py --iterations 1000
~~~

This overwrites benchmark_results.json with separate development smoke, detector,
XAI, middleware and loopback HTTP measurements. Use --output for a separate run.

For real HTTP latency through SecretBook's actual configured middleware, views and
templates, run from Project:

~~~powershell
$env:WAF_PIPELINE='legacy'
$env:WAF_MODE='block'
.\SecretBook\venv\Scripts\python.exe benchmark_secretbook.py --iterations 100
Remove-Item Env:WAF_PIPELINE, Env:WAF_MODE
~~~

Results go to secretbook_latency_results.json. This runs 700 measured anonymous
requests on a temporary local WSGI server and shuts it down. It measures real HTML
responses and explained blocks, not authenticated database workloads, browser assets,
TLS or concurrency. The original demo database is not modified.

The final combined dataset and splits are in ../data/final/. build_dataset.py,
train.py and verify_artifacts.py use the separate Python 3.10 environment described
in ../PROJECT_CONTEXT.md. Training requirements are ../requirements-training.txt.

Final pooled test accuracy is 98.17%; CSIC subset accuracy is 95.72%. The test was
reused after a disclosed smoke-driven training adaptation. The 20/20 smoke suite
overlaps deployment development and must never be presented as independent accuracy.

For the new candidate, use `python -m experiments.request_v3.verify` from
Project with this venv. The new fit, final-evaluation and audit commands are recorded
in ../experiments/request_v3/README.md. Frozen experiments refuse accidental refits.

## Scope

This remains a research prototype. It supplements parameterized queries, Django
escaping/CSRF, access control, secure deployment and other controls. It does not
classify exploit types, inspect headers or uploaded file contents, guarantee detection,
or establish production/concurrent-load performance.
