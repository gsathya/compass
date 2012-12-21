var compassModule = angular.module("Compass", ['ui'])

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
  
  // We set this to true if the request
  // asked for all of the relays
  $scope.full_request = false

  $scope.request = function(success_cb) {

    if ($scope.state != 'sorting') {
      $scope.state = 'loading'
    }

    if ($scope.query.top == '-1') {
      $scope.full_request = true
    } else {
      $scope.full_request = false
    }

    $http.get('result.json',{"params":$scope.query})
      .success(function(data) {
        if (data.results.length > 0) {
          $scope.data = data
          $scope.state = "loaded"
          if (success_cb != null){
            success_cb
          }
        }
        else { 
          $scope.state = "result_empty"
        }
      })
  };

  $scope.reset = function() {
    $scope.state="hidden"
  }

  $scope.setsort = function(field,init) {
    $scope.state = 'sorting'

    if (field == $scope.query.sort) {
      $scope.query.sort_reverse = !($scope.query.sort_reverse)
    } 
    else {
      $scope.query.sort = field
      $scope.query.sort_reverse = init
    }
    
    if (! $scope.full_request) {
      // We don't have the data we need to sort
      $scope.request($scope.query, function() {
        $scope.table.sort = $scope.query.sort
        $scope.table.reverse = $scope.query.sort_reverse
      });
    } 
    else {
      $scope.table.sort = $scope.query.sort
      $scope.table.reverse = $scope.query.sort_reverse
    }

  }

  $http.get("static/data/cc.json").success(function(data) {
    $scope.cc_data = data
  })

  $scope.country_select = {
    allowClear: true,
    width: "element",
  }

})
