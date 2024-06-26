import hashlib
import logging
import os
import ssl

logger = logging.getLogger(__name__)


def generate_cfn_template(
    oidc_provider_url, oidc_provider_aud, oidc_provider_thumbprint
):
    if not oidc_provider_thumbprint:
        oidc_provider_thumbprint = get_cert_chain(oidc_provider_url)

    __location__ = os.path.realpath(
        os.path.join(os.getcwd(), os.path.dirname(__file__))
    )
    template_file = os.path.join(__location__, "cfn.yaml.tpl")
    return replace_placeholders(
        template_file,
        oidc_provider_url=oidc_provider_url,
        oidc_provider_aud=oidc_provider_aud,
        oidc_provider_thumbprint=oidc_provider_thumbprint,
        oidc_provider_iam_name=strip_url_prefix(oidc_provider_url),
    )


def replace_placeholders(template_file, **kwargs):
    """
    Replaces placeholders in a template file with the provided variables.

    Args:
        template_file (str): Path to the template file.
        **kwargs: Key-value pairs of variables to replace in the template.

    Returns:
        str: The modified content of the template file with placeholders replaced.
    """
    with open(template_file, "r") as file:
        template_content = file.read()

    for placeholder, value in kwargs.items():
        template_content = template_content.replace(
            f"{{{{ {placeholder} }}}}", str(value)
        )

    return template_content


def strip_url_prefix(url):
    """
    Strips the 'http://' or 'https://' prefix from a URL string.

    Args:
        url (str): The URL string to be processed.

    Returns:
        str: The URL string with the 'http://' or 'https://' prefix removed.
    """
    if url.startswith("http://"):
        return url[7:]
    elif url.startswith("https://"):
        return url[8:]
    else:
        return url


def get_cert_chain(url, port: int = 443):
    hostname = url.split("/")[2]

    # Create a context for SSL connection
    context = ssl.create_default_context()
    # Connect to the server and retrieve the certificate
    with context.wrap_socket(ssl.socket(), server_hostname=hostname) as sock:
        sock.connect((hostname, port))
        cert = sock.getpeercert(binary_form=True)
    # Compute the thumbprint (SHA-1 hash) of the certificate
    thumbprint = hashlib.sha1(cert).hexdigest().lower()
    return thumbprint
