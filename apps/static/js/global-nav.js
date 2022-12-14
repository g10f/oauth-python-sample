(function() {
  /*
  <ul class="nav navbar-nav" id="user_apps" data-user-apps-url="#{ user-apps-url }" data-app-uuid="" data-logout-url=""></ul>
  */
  var add_user_apps_to_navbar, get_app_item, get_text;

  $(function() {
    var app_uuid, logout_url, user_apps, user_apps_url, user_uuid;
    user_apps = $('#user_apps');
    if (user_apps.length > 0) {
      user_apps_url = user_apps.data("user-apps-url");
      app_uuid = user_apps.data("app-uuid");
      user_uuid = user_apps.data("user-uuid");
      logout_url = user_apps.data("logout-url");
      if ((user_apps_url !== "") && (app_uuid !== "") && (user_uuid !== "")) {
        return add_user_apps_to_navbar(user_apps_url, app_uuid, logout_url, user_uuid);
      }
    }
  });

  get_app_item = function(app, app_uuid, dropdown = false) {
    var css_class;
    css_class = (app_uuid && app.id === app_uuid) ? "active" : "";
    if (dropdown) {
      return `<li><a class=\"dropdown-item ${css_class}\" href=\"${app.link.href}\">${app.link.title}</a></li>`;
    } else {
      return `<li class=\"nav-item\"><a class=\"nav-link ${css_class}\" href=\"${app.link.href}\">${app.link.title}</a></li>`;
    }
  };

  get_text = function(data, key) {
    if (data.text && data.text[key]) {
      return data.text[key];
    } else {
      return key;
    }
  };

  add_user_apps_to_navbar = function(user_app_url, app_uuid, logout_url, user_uuid) {
    var request, url;
    url = user_app_url.replace("/me/", `/${user_uuid}/`);
    request = $.ajax({
      url: url,
      dataType: "jsonp",
      ifModified: true,
      cache: true
    });
    return request.done(function(data) {
      var apps, i, items, j, k, more, profile_link, ref, subitems, thumbnail;
      if ((data.error && data.code === 401) || (data.id !== user_uuid)) {
        // if logout_url
        //  $(location).attr('href', logout_url)
        return console.debug(data.error);
      } else {
        items = [];
        apps = data.apps.filter(function(app) {
          return app.link.global_navigation;
        });
        more = get_text(data, 'More');
        if (apps.length < 4) {
          $.each(apps, function(idx, app) {
            return items.push(get_app_item(app, app_uuid));
          });
        } else {
          for (i = j = 0; j <= 2; i = ++j) {
            items.push(get_app_item(apps[i], app_uuid));
          }
          subitems = [`<li class=\"nav-item dropdown\"><a href=\"{ data.more.href }\" class=\"nav-link dropdown-toggle\" data-bs-toggle=\"dropdown\">${data.more.title}</a><ul class=\"dropdown-menu\">`];
          for (i = k = 3, ref = apps.length - 1; (3 <= ref ? k <= ref : k >= ref); i = 3 <= ref ? ++k : --k) {
            subitems.push(get_app_item(apps[i], app_uuid, true));
          }
          subitems.push("</ul></li>");
          items.push(subitems.join(''));
        }
        $('#user_apps').html(items.join(''));
        if (data.picture_30x30) {
          thumbnail = `<img class=\"dwbn-icon-user\" width=\"30\" height=\"30\" alt=\"\" src=\"${data.picture_30x30.href}\">`;
        } else {
          thumbnail = "<i class=\"glyphicon glyphicon-user\"></i>";
        }
        profile_link = `<a href=\"${data.profile.href}\">${thumbnail} ${data.profile.title}</a>`;
        $('#user-profile').html(profile_link);
        return $('#logout a span').text(data.logout.title);
      }
    });
  };

}).call(this);

//# sourceMappingURL=global-nav.js.map
