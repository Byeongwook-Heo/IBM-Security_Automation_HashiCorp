FROM docker.io/hashicorp/vault-radar:0.49.0@sha256:2073885121c6da300670c607cb43ee65217a50283da083dffc602797ee8baa58 AS vault_radar

FROM public.ecr.aws/aws-cli/aws-cli@sha256:c1930b0b4400b03267d06d15e34e7e605c9a72b8bb123de30d4ad8fa4e00da8c

RUN dnf install -y \
      bash \
      findutils \
      git \
      jq \
      shadow-utils \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && groupadd --gid 65532 vault-radar \
    && useradd --uid 65532 --gid vault-radar --create-home --shell /sbin/nologin vault-radar

COPY --from=vault_radar /bin/vault-radar /usr/local/bin/vault-radar

ENV HOME=/home/vault-radar
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT []
CMD ["vault-radar", "--help"]
