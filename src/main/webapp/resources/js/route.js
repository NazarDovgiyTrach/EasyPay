var map, directionsDisplay, directionsService, markers = [];

$(function () {
    initialize(
        document.getElementById("route-map"),
        {center: {lat: 50.4501, lng: 30.5234}, zoom: 12}
    );
});

function initialize(el, initOptions) {
    directionsService = new google.maps.DirectionsService();
    map = new google.maps.Map(el, initOptions);
}

function setDirections(arr) {
    if(directionsDisplay != null) {
        directionsDisplay.setMap(null);
        directionsDisplay = null;
        setMapOnAll(null);
    }

    directionsDisplay = new google.maps.DirectionsRenderer({suppressMarkers: true});
    directionsDisplay.setMap(map);

    window.setTimeout(function () {
        calcRoute(arr);
    }, 600);
}

function calcRoute(arr) {
    var waypts = [];

    $.each(arr, function (index, element) {
        waypts.push({
            location: new google.maps.LatLng(element.address.lat, element.address.lng),
            stopover: true
        });

        addMarker(new google.maps.LatLng(element.address.lat, element.address.lng))
    });

    start = new google.maps.LatLng(arr[0].address.lat, arr[0].address.lng);
    end = new google.maps.LatLng(arr[arr.length - 1].address.lat, arr[arr.length - 1].address.lng);

    if (waypts.length > 1) {
        var request = {
            origin: start,
            destination: end,
            waypoints: waypts,
            optimizeWaypoints: true,
            travelMode: google.maps.DirectionsTravelMode.WALKING
        };

        directionsService.route(request, function (response, status) {
            if (status === google.maps.DirectionsStatus.OK) {
                directionsDisplay.setDirections(response);
            }
        });
    } else {
        map.panTo(start);
        map.setZoom(17);
    }
}

function setMapOnAll(map) {
    for (var i = 0; i < markers.length; i++) {
        markers[i].setMap(map);
    }
}

function addMarker(location) {
    var marker = new google.maps.Marker({
        position: location,
        map: map
    });
    markers.push(marker);
}

function clearMarkers() {
    setMapOnAll(null);
}