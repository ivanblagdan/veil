# Installation integration test, NOT a deployment/service image.
# The final stage deliberately contains neither Rust, Python nor the source checkout.
FROM rust:1.92-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock assets.lock.json ./
COPY src/ src/
COPY tests/ tests/
COPY scripts/install scripts/install
COPY README.md LICENSE ./
COPY docs/ docs/
RUN cargo test --locked && python3 -m unittest discover -s tests -p '*_test.py' \
    && ./scripts/install --prefix /opt/veil

FROM debian:bookworm-slim AS verify
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/veil /opt/veil
ENV PATH="/opt/veil/bin:${PATH}"
WORKDIR /tmp
USER 65534:65534
RUN --network=none veil verify-artifacts \
    && printf 'Email alex@example.com\n' > original.txt \
    && veil redact < original.txt > redacted.txt \
    && ! grep -q alex@example.com redacted.txt \
    && ! grep -q '\[\[VEIL:' redacted.txt \
    && veil cloak --vault text.vault < original.txt > protected.txt \
    && ! grep -q alex@example.com protected.txt \
    && veil uncloak --vault text.vault < protected.txt > restored.txt \
    && cmp original.txt restored.txt \
    && printf 'Email alex@example.com\r\n\r\nlast' | veil cloak --input lines --vault lines.vault > lines.txt \
    && veil uncloak --input lines --vault lines.vault < lines.txt > restored-lines.txt \
    && printf 'Email alex@example.com\n\nlast\n' | cmp - restored-lines.txt \
    && printf '{"email":"alex@example.com","n":123456789012345678901234567890}\n' > original.json \
    && veil cloak --input json --vault json.vault < original.json > protected.json \
    && veil uncloak --input json --vault json.vault < protected.json > restored.json \
    && cmp original.json restored.json \
    && veil cloak --input jsonl --vault jsonl.vault < original.json > protected.jsonl \
    && veil uncloak --input jsonl --vault jsonl.vault < protected.jsonl > restored.jsonl \
    && cmp original.json restored.jsonl
