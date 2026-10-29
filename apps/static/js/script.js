/*
 * Sample Client side script:
 *
 * The access_token from the sso provider is used to make a http request for same user data.
 *
 */
/*
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });
*/
$(function() {
	var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
	var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
		return new bootstrap.Tooltip(tooltipTriggerEl)
	});

	// The state of the login link the user clicked is kept in the sessionStorage. The callback only accepts a
	// state that is identical to this value. That proves the response belongs to a login started in this
	// browser (CSRF protection, RFC 6749 section 10.12) and that the values in the state were not changed.
	var STATE_STORAGE_KEY = 'oauth2_implicit_state';

	function storeState(state) {
		try {
			sessionStorage.setItem(STATE_STORAGE_KEY, state);
		} catch (e) {
			console.error('The state can not be stored in the sessionStorage.', e);
		}
	}

	// Returns the stored state and removes it, so that every state is accepted only once.
	function popStoredState() {
		try {
			var state = sessionStorage.getItem(STATE_STORAGE_KEY);
			sessionStorage.removeItem(STATE_STORAGE_KEY);
			return state;
		} catch (e) {
			console.error('The state can not be read from the sessionStorage.', e);
			return null;
		}
	}

	// The state is url safe base64 encoded JSON without padding (see build_state in oauth2/views.py).
	function decodeState(state) {
		var base64 = state.replace(/-/g, '+').replace(/_/g, '/');
		while (base64.length % 4) {
			base64 += '=';
		}
		return JSON.parse(atob(base64));
	}

	// Only http(s) urls are used for links and images, a "javascript:" url from the userinfo must not be executed.
	function safeUrl(url) {
		try {
			var parsed = new URL(url, location.href);
			if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
				return parsed.href;
			}
		} catch (e) {
			// not a valid url
		}
		return null;
	}

	function showError(message) {
		$('<div class="alert alert-danger" role="alert"></div>').text(message).insertBefore('#info_table');
	}

	// All values from the userinfo are inserted with text() or attr(), never as html, because the user can
	// edit them in the sso provider.
	function infoRow(key, $value) {
		return $('<tr></tr>').append($('<td></td>').text(key), $('<td></td>').append($value));
	}

	function pictureRow(src) {
		var hasPicture = Boolean(src);
		var $image = $('<img id="id_image" width="100">');
		$image.attr('src', hasPicture ? src : $("#info_table").data("default-image"));
		var $deleteButton = $('<button id="id_picture_delete" class="btn btn-default">Delete</button>');
		$deleteButton.prop('disabled', !hasPicture);
		return infoRow('picture', [
			$image,
			$('<input id="id_picture" name="picture" type="file">'),
			$('<button id="id_picture_update" class="btn btn-default" disabled>Update</button>'),
			$deleteButton
		]);
	}

	function applicationList(applications) {
		var $list = $('<ul></ul>');
		$.each(applications, function(idx, app) {
			var $link = $('<a></a>').text(app.links.app.title);
			var href = safeUrl(app.links.app.href);
			if (href) {
				$link.attr('href', href);
			}
			$('<li></li>').append($link).appendTo($list);
		});
		return $list;
	}

	// Remember the state of the login link before the browser leaves the page.
	$('a[data-client-id]').on('click', function() {
		var state = new URL(this.href).searchParams.get('state');
		if (state) {
			storeState(state);
		}
	});

	// userinfo_endpoints must be set in the template
	// First, parse the query string
	var params = {}, queryString = location.hash.substring(1), regex = /([^&=]+)=([^&]*)/g, m;
	while (m = regex.exec(queryString)) {
		params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
	}

	var picture_endpoint;
	if (params.access_token) {
		// The token must not stay in the address bar and the browser history.
		history.replaceState(null, '', location.pathname + location.search);

		var storedState = popStoredState();
		if (!params.state || params.state !== storedState) {
			showError('The login response does not belong to a login started in this browser and is ignored.');
			return;
		}
		// The state is identical to the one we created, so the endpoints in it can be trusted.
		var data = decodeState(params.state);
		picture_endpoint = data.picture_endpoint;

		// get userinfos if we have an access token
		$.ajax({
			url: data.userinfo_endpoint,
			type: 'GET',
			headers: {Authorization: 'Bearer ' + params.access_token}
		}).done(function(data) {
			// add the userinfos to the table with id="info_table"
			var rows = [];
			var has_picture = false;
			$.each(data, function(key, val) {
				if (key == 'picture') {
					has_picture = true;
					var picture_url = null;
					if (val && val['@id']) {
						picture_url = safeUrl(val['url']);
					} else if (picture_endpoint) {
						picture_url = safeUrl(val && val.url);
					} else {
						picture_url = safeUrl(val);
					}
					if (picture_endpoint) {
						rows.push(pictureRow(picture_url));
					} else if (picture_url) {
						rows.push(infoRow(key, $('<img width="100">').attr('src', picture_url)));
					}
				}
				else if (key == 'applications') {
					rows.push(infoRow(key, applicationList(val)));
				}
				else {
					rows.push(infoRow(key, document.createTextNode(JSON.stringify(val))));
				}
			});
			if (!has_picture && picture_endpoint) {
				rows.push(pictureRow(null));
			}
			$('#info_table').append(rows);
			$("#id_picture" ).on("change", handleFileSelect);
			$("#id_picture_update").on("click", updatePicture);
			$("#id_picture_delete").on("click", deletePicture);
			$("#id_image").on( "load", function() {
				if ($(this).attr("src") != $("#info_table").data("default-image")) {
					$("#id_picture_delete").removeAttr("disabled");
					$("#id_picture_update").text('Update');
				} else {
					$("#id_picture_delete").attr("disabled", "disabled");
				}
			});
		});
	}
	// picture update handling
	var fileArrayBuffer;
	var file_type;
	function deletePicture() {
		$.ajax({
			url: picture_endpoint,
			type: 'DELETE',
			headers: {Authorization: 'Bearer ' + params.access_token}
		}).done(function(data, textStatus, request) {
			$("#id_image").attr('src', $("#info_table").data("default-image"));
		});
	}

	function updatePicture() {
		$(this).prop('disabled', true).text('Loading ...');
		$.ajax({
			url: picture_endpoint,
			type: 'POST',
			contentType: file_type,
			data: fileArrayBuffer,
			headers: {Authorization: 'Bearer ' + params.access_token},
			processData: false
		}).done(function(data, textStatus, request) {
			// Location Header does not work, probably because the location does not support CORS header
			// var location = request.getResponseHeader('Location');
			var location = safeUrl(data.url);
			if (location) {
				$("#id_image").attr('src', location);
			}
		});
	}

	function handleFileSelect(evt) {
		var file = evt.target.files[0];
		if (!file.type.match('image.*')) {
			alert('Only Image files are supported!')
			return;
		}
		if (file.size > 5242880) {
			alert('Max Size is 5 MB!')
			return;
		}
		var reader = new FileReader();
		reader.onload = function(e) {
			fileArrayBuffer = e.target.result;
			file_type = file.type;
		};
		reader.readAsArrayBuffer(file);
		$("#id_picture_update").removeAttr("disabled");
	}
});
