
QK_ERROR = "error"
QK_ERROR_DETAIL = "error_detail"
QK_NEXT = "next"
OIDC_ATTRS = (
	"client_id",
	"redirect_uri",
	"response_type",
	"scope",
	"nonce",
	"prompt",
	"code_challenge",
	"code_challenge_method",
)
OIDC_COOKIE_VUE_REDIRECT = "redirect"
OIDC_COOKIE_VUE_LOGIN = "login"
OIDC_COOKIE_VUE_ABORT = "abort"
OIDC_COOKIE_CHOICES = (
	OIDC_COOKIE_VUE_REDIRECT,
	OIDC_COOKIE_VUE_LOGIN,
	OIDC_COOKIE_VUE_ABORT,
)
OIDC_PROMPT_NONE = "none"
OIDC_PROMPT_LOGIN = "login"
OIDC_PROMPT_CONSENT = "consent"
OIDC_PROMPT_SELECT_ACCOUNT = "select_account"
OIDC_ALLOWED_PROMPTS = {
	OIDC_PROMPT_NONE,
	OIDC_PROMPT_LOGIN,
	OIDC_PROMPT_CONSENT,
	OIDC_PROMPT_SELECT_ACCOUNT,
}