# One image for core, public and agent; the stack picks the command.
#
# The base is pinned by digest (python:3.13-slim, multi-arch index, 2026-11-05) so a
# rebuild is the same image until someone moves the pin on purpose. Dependencies come
# from requirements.lock with --require-hashes: a package that changed under the same
# version number fails the build instead of shipping.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TGXMON_CATALOGUE=/app/catalogue \
    TGXMON_DB=/data/monitor.db \
    TGXMON_PUBLIC_DIR=/public

# uid 10001: no clash with a host account, so a file the container writes on Gluster
# is never mistaken for someone's. The stack adds the hosts' docker group (gid 1000)
# where a service must read 2770 directories such as the cluster documentation.
RUN groupadd --gid 10001 tgxmon \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app \
       --shell /usr/sbin/nologin tgxmon

WORKDIR /app

COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock

# The package itself. setuptools is the build backend only: installed from a hash,
# used without build isolation (so nothing unpinned is fetched), then removed.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN printf '%s\n' \
      'setuptools==84.2.1 --hash=sha256:3ff8b3b5492a0aa66960f4419365a86b84e013070d4313e4d4a6894f5d64d6bc' \
      > /tmp/build.txt \
    && pip install --require-hashes --no-deps -r /tmp/build.txt \
    && pip install --no-deps --no-build-isolation . \
    && pip uninstall -y setuptools \
    && rm -rf /tmp/build.txt build src/*.egg-info

# The catalogue ships in the image, so the running checks always match a commit.
COPY catalogue ./catalogue

USER 10001:10001
EXPOSE 8000 8080 8001

# core's liveness: /livez reports only the scheduler's own tick, never a target's
# state, so a down target can never restart-loop the monitor. public and agent
# override this in stack.yml.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/livez', timeout=4)"]

CMD ["tgx-monitor", "run"]
