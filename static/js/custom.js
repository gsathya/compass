function addListener(){
    $('.sort').each(function(index, element) {
        var url = window.location;
        var origin = window.location.origin;
        var path = window.location.pathname;
        var args = parseArgs(url);
        args['sort'] = this.id;
        url = origin+path+'?'+$.param(args);
        $(this).attr('href', url);
    });
}

function parseArgs(query){
    var newQuery = {}, key, value;
    query = String(query);
    query = query.split("?")[1];
    query = query.split("&");
    $.each(query, function(i, arg){
        arg = arg.split("=");
        if (arg[0] != "sort") {
            newQuery[arg[0]] = arg[1];
        }
    });
    return newQuery;
}

function doAjax(){
    var path = window.location.search;
    if(path) {
        console.log("Sending request");
        $.ajax({
            url: "result"+path,
            type: "GET",
        }).done(function(data) {
            $('#result').append(data);
            $('html, body').animate({ 
                scrollTop: $('#result').offset().top
            }, 1000);
        });
    }
}
