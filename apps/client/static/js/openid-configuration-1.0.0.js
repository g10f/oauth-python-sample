django.jQuery(document).ready(function($) {
	$("input[name='openid-configuration']").click(function() {

		var url = $("input[name='issuer']").val()
		if (url !== '') {
			url += "/.well-known/openid-configuration";
			var request = $.ajax({
				type: 'GET',
				url: url
			});
			request.done(function( oid_config ) {
				if ( console && console.log ) {
					console.log( "data:", oid_config );
				}
				$("input[name='authorization_endpoint']").val(oid_config.authorization_endpoint);
				$("input[name='token_endpoint']").val(oid_config.token_endpoint);
				$("input[name='end_session_endpoint']").val(oid_config.end_session_endpoint);
				// $("input[name='revoke_uri']").val(oid_config.revoke_uri);
				$("input[name='userinfo_endpoint']").val(oid_config.userinfo_endpoint);
				$("input[name='certs_uri']").val(oid_config.jwks_uri);
				$("input[name='profile_uri']").val(oid_config.profile_uri);
				$("input[name='check_session_iframe']").val(oid_config.check_session_iframe);
				$("input[name='jwks_uri']").val(oid_config.jwks_uri);
			});
		}
	});
});
