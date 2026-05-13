FROM gh-agent-broker:sandbox-e2e AS broker

FROM ghcr.io/hostinger/hvps-hermes-agent:latest

USER root
COPY --from=broker /usr/local/bin/gh-agent-broker-cli /usr/local/bin/gh-agent-broker-cli
COPY skills/gh-agent-broker /opt/hermes-sandbox/skills/gh-agent-broker
COPY testdata/sandbox-hermes-auth/worker.sh /usr/local/bin/sandbox-hermes-auth-probe
RUN chmod 0755 /usr/local/bin/sandbox-hermes-auth-probe \
	&& chmod 0755 /usr/local/bin/gh-agent-broker-cli \
	&& chmod -R a+rX /opt/hermes-sandbox/skills

USER 10000:10000
ENTRYPOINT ["/usr/local/bin/sandbox-hermes-auth-probe"]
