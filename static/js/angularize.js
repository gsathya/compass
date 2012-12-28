var compassModule = angular.module("Compass", ['ui','oblique.directives','oblique.filters'])

compassModule.value('ui.config', {
   select2: {
      allowClear: true,
      width: "element",
   }
});

compassModule.controller('CompassCtrl',function CompassCtrl($scope,$http,$location) {

  $scope.state = "hidden"
  $scope.query = {
    exit_filter:"all_relays",
    links:true,
    sort:'cw',
    country: null
  }

  /** Watch the location bar to allow us to load saved searches **/
  $scope.$watch($location.search(), function(newv, oldv, scope) {
    if ($location.search().top) {
      $scope.query=$location.search()
      $scope.request()
    }
  })

  /** Make a sorting request
   *
   * Call 'success_cb' if the request is successful
   */
  $scope.ajax_sort = function(sortBy, invert, success_cb) {
    $scope.query.sort = sortBy
    $scope.query.sort_reverse = invert

    //Update the location bar to track sorting
    $location.search($scope.query)

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

    //Set the location bar for this search
    $location.search($scope.query)

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
