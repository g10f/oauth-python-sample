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

	function randomString(len) {
		charset='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		for( var i=0; i < len; i++ ) {
            text += charset.charAt(Math.floor(Math.random() * charset.length));
        }
    	return text;
	}
	//#sessionStorage

	function imageHtml(src) {
		var status = '';
		if (!src) {
			src = $("#info_table").data("default-image");
			status = 'disabled="disabled"';
		}
		var item = '<tr><td>picture</td><td><image id="id_image" src=' + src + ' width="100px" />';
		item += '<input id="id_picture" name="picture" type="file">';
		item += '<button id="id_picture_update" class="btn btn-default" data-loading-text="Loading ..." disabled="disabled">Update</button>';
		item += '<button id="id_picture_delete" class="btn btn-default" ' + status + '>Delete</button>';
		item += '</td></tr>';
		return item;
	} 
	// userinfo_endpoints must be set in the template
	// First, parse the query string
	var params = {}, queryString = location.hash.substring(1), regex = /([^&=]+)=([^&]*)/g, m;
	while (m = regex.exec(queryString)) {
		params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
	}
		
	if (params.access_token){
		data = $.parseJSON($.base64.decode(params.state));
		// TODO: check state has not been tampered with. (check data.nonce)   
		// get userinfos if we have an access token
		var picture_endpoint = data.picture_endpoint;

		$.ajax({
			url: data.userinfo_endpoint,
			type: 'GET',
			headers: {Authorization: 'Bearer ' + params.access_token}
		}).done(function(data) {
			// add the userinfos to the table with id="info_table"
			var items = [];
			var has_picture = false;
			$.each(data, function(key, val) {
				var item;
				if (key == 'picture'){
					has_picture = true;
					if (picture_endpoint) {
						item = imageHtml(JSON.stringify(val.url));
					} else {
                        picture_url = ''
                        if (val['@id']){
                            if (val['url']) {
                                picture_url = val['url'];
                            }
                        }
                        else {
                            picture_url = val
                        }
                        if (picture_url) {
                            item = '<tr><td>'  + key + '</td><td><image src=' + JSON.stringify(picture_url) + ' width="100px" /></td></tr>';
                        }

					}
				}
				else if (key == 'applications'){
					var apps = [];
					$.each(val, function(idx, app) {
						apps.push('<li><a href="' + app.links.app.href +  '">' + app.links.app.title + ' </a></li>');
					});				
					item = '<tr><td>'  + key + '</td><td>' + apps.join('') + '</td></tr>';					
				}
				else{
					item = '<tr><td>'  + key + '</td><td>' + JSON.stringify(val) + '</td></tr>';					
				}
				items.push(item);
			});
			if (!has_picture && picture_endpoint) {
				item = imageHtml("");
				items.push(item);
			}
			$(items.join('')).appendTo('#info_table');
			$("#id_picture" ).on("change", handleFileSelect);
			$("#id_picture_update").on("click", updatePicture);
			$("#id_picture_delete").on("click", deletePicture);
			$("#id_image").on( "load", function() {
				if ($(this).attr("src") != $("#info_table").data("default-image")) {
					$("#id_picture_delete").removeAttr("disabled");
					$("#id_picture_update").button('reset');
				} else {
					$("#id_picture_delete").attr("disabled", "disabled");
				}
			});			
		});
		//window.location.hash = '';
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
		var $btn = $(this).button('loading');
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
			var location = data.url;
			$("#id_image").attr('src', location);
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
