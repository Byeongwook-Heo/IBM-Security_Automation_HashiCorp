import os

ENTERPRISE_PRODUCTS = [
    "qradar",
    "guardium",
    "instana",
    "turbonomic",
    "kubecost",
    "concert",
    "vault",
    "boundary",
    "nomad",
    "vault_radar",
]


def enterprise_status():
    """Return redacted enterprise image/license configuration status.

    The portal must never expose actual license values, entitlement keys, or
    registry credentials. This endpoint only tells operators whether the
    expected secret references are configured in the runtime environment.
    """
    return {
        product: {
            "edition": "enterprise",
            "image_configured": bool(
                os.getenv(f"{product.upper()}_IMAGE_URI")
                or os.getenv(f"{product.upper()}_ENTERPRISE_IMAGE_URI")
            ),
            "license_configured": bool(
                os.getenv(f"{product.upper()}_LICENSE_SECRET_ARN")
                or os.getenv(f"{product.upper()}_TOKEN")
            ),
            "secret_values_redacted": True,
        }
        for product in ENTERPRISE_PRODUCTS
    }
