(function () {
	var el = document.getElementById("better-auth-oauth-popup");
	if (!el) return;
	var payload;
	try {
		payload = JSON.parse(el.textContent || "");
	} catch (e) {
		return;
	}
	var target = window.opener || window.parent;
	if (target && target !== window) {
		try {
			target.postMessage(
				{
					type: payload.type,
					nonce: payload.nonce,
					token: payload.token,
					redirectTo: payload.redirectTo,
					error: payload.error,
				},
				payload.targetOrigin,
			);
		} catch (e) {}
	}
	window.close();
})();
