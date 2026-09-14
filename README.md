# Explainable Django request detector

SecretBook is a research demo with a character CNN trained on SQLi, XSS and CSIC
request data. Paths/queries and supported textual bodies are normalized using the
same code as training. Overlapping 256-character windows cover every admitted
character, with maximum-window scoring and logit-gradient explanations for blocks.

## Run

From this directory:

~~~powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
~~~

The versioned model and matching vocabulary are bundled in models/. In the full research workspace, ../attack_model.pt and ../char_dict.pkl take precedence.
Configure SECRET_KEY, DEBUG and SMTP settings through the local environment/.env;
do not publish their values. ALLOWED_HOSTS defaults to local hosts.

Optional WAF settings:
- WAF_ATTACK_THRESHOLD: omitted/empty uses the checkpoint's selected threshold (0.45).
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

Known navigation paths bypass scoring only for query-free GET/HEAD requests whose
body has been verified empty. Bodies and queries on those paths are inspected.
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

21 tests cover middleware, bounds, explanations, ownership and deletion behavior,
including a saved-model integration check. Tests use a separate in-memory database.

The research/ directory contains the current paper, figures and measured results. Raw datasets, training scripts and historical runs are maintained in the separate local research workspace and are not included in this application repository. The commands below require that full workspace.

From the parent Project folder:

~~~powershell
.\SecretBook\venv\Scripts\python.exe benchmark_waf.py --iterations 1000
~~~

This overwrites benchmark_results.json with separate development smoke, detector,
XAI, middleware and loopback HTTP measurements. Use --output for a separate run.

For real HTTP latency through SecretBook's actual configured middleware, views and
templates, run from Project:

~~~powershell
.\SecretBook\venv\Scripts\python.exe benchmark_secretbook.py --iterations 100
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

## Scope

This remains a research prototype. It supplements parameterized queries, Django
escaping/CSRF, access control, secure deployment and other controls. It does not
classify exploit types, inspect headers or uploaded file contents, guarantee detection,
or establish production/concurrent-load performance.
