###
<ul class="nav navbar-nav" id="user_apps" data-user-apps-url="#{ user-apps-url }" data-app-uuid="" data-logout-url=""></ul>
###

$ ->
  user_apps = $('#user_apps')
  if user_apps.length > 0
    user_apps_url = user_apps.data("user-apps-url")
    app_uuid = user_apps.data("app-uuid")
    user_uuid = user_apps.data("user-uuid")
    logout_url = user_apps.data("logout-url")
    if (user_apps_url isnt "") and (app_uuid isnt "") and (user_uuid isnt "")
      add_user_apps_to_navbar(user_apps_url, app_uuid, logout_url, user_uuid)


###
IE 8 arrays don't have a filter function
###
do -> Array::filter ?= (callback) ->
  element for element in this when callback element


get_app_item = (app, app_uuid) ->
  css_class = if (app_uuid and app.id is app_uuid) then "active" else ""
  return "<li class=\"#{ css_class }\"><a href=\"#{ app.link.href }\">#{ app.link.title }</a></li>";


get_text = (data, key) ->
  if data.text and data.text[key]
    data.text[key]
  else
    key


add_user_apps_to_navbar = (user_app_url, app_uuid, logout_url, user_uuid) ->
  url = user_app_url.replace("/me/", "/#{ user_uuid}/");
  request = $.ajax(
    url: url,
    dataType: "jsonp",
    ifModified: true,
    jsonpCallback: 'user_apps',
    cache: true)

  request.done((data) ->
    if (data.error and data.code is 401) or (data.id isnt user_uuid)
      if logout_url
        $(location).attr('href', logout_url)
    else
      items = []
      apps = data.apps.filter((app) -> app.link.global_navigation)
      more = get_text(data, 'More')
      if apps.length < 4
        $.each(apps, (idx, app) -> items.push(get_app_item(app, app_uuid)))
      else
        items.push(get_app_item(apps[i], app_uuid)) for i in [0..2]
        subitems = ["<li class=\"dropdown\"><a href=\"{ data.more.href }\" class=\"dropdown-toggle\" data-toggle=\"dropdown\">#{ data.more.title } <b class=\"caret\"></b></a><ul class=\"dropdown-menu\">"]
        subitems.push(get_app_item(apps[i], app_uuid)) for i in [3..apps.length - 1]
        subitems.push("</ul></li>")
        items.push(subitems.join(''))

      $('#user_apps').html(items.join(''))

      if data.picture_30x30
        thumbnail = "<img class=\"dwbn-icon-user\" width=\"30\" height=\"30\" alt=\"\" src=\"#{ data.picture_30x30.href }\">"
      else
        thumbnail = "<i class=\"glyphicon glyphicon-user\"></i>"
      profile_link = "<a href=\"#{ data.profile.href }\">#{ thumbnail } #{ data.profile.title }</a>"
      $('#user-profile').html(profile_link)
      $('#logout a span').text(data.logout.title)
  )
