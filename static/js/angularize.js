var compassModule = angular.module("Compass", ['ui','oblique.directives'])

compassModule.value('ui.config', {
   select2: {
      allowClear: true,
      width: "element",
   }
});

compassModule.controller('CompassCtrl',function CompassCtrl($scope,$http) {

  $scope.state = "hidden"
  $scope.query = {
    exit_filter:"all_relays",
    links:true,
    sort:'cw',
    sort_reverse:true,
    country: null
  }
  $scope.table = {
    sort: 'cw',
    reverse: true
  }

  /** Make a sorting request
   *
   * Call 'success_cb' if the request is successful
   */
  $scope.ajax_sort = function(sortBy, invert, success_cb) {
    $scope.query.sort = sortBy
    $scope.query.sort_reverse = invert

    $http.get('result.json',{"params":$scope.query})
      .success(function(data) {
        if (data.results.length > 0) {
          $scope.data = data

          if (success_cb !== null){
            success_cb()
          }

          $('body').animate({scrollTop:$("div#result_table").offset().top},500)
        }
        else {
          $scope.state = "result_empty"
        }
      })

  }

  /**  Make a data request from the form
   *
   * Call 'success_cb' if the request is successful
   */
  $scope.request = function(success_cb) {
    $scope.state = 'loading'

    $http.get('result.json',{"params":$scope.query})
      .success(function(data) {
        if (data.results.length > 0) {
          $scope.data = data
          $scope.state = "loaded"
          if (success_cb != null){
            success_cb()
          }
          $('body').animate({scrollTop:$("div#result_table").offset().top},500)
        }
        else {
          $scope.state = "result_empty"
        }
      })
  };

  $scope.reset = function() {
    $scope.state="hidden"
  }

  $http.get("static/data/cc.json").success(function(data) {
    $scope.cc_data = data
  })

  $scope.country_select = {
    allowClear: true,
    width: "element",
  }

})
