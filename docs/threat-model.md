# Threat Model

This document describes the threat model for the integrated security lab.

## Key decisions
- QRadar is the central SIEM/correlation layer.
- Security Lake and S3 Object Lock are raw retention layers.
- The portal provides summary, correlation, approval, automation, evidence, and deep links.
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Details
See root README, Terraform modules, connector skeletons, and portal code for executable examples.
