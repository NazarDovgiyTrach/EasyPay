package com.softserveinc.ch067.easypay.util;

import com.peertopark.java.geocalc.DegreeCoordinate;
import com.peertopark.java.geocalc.EarthCalc;
import com.peertopark.java.geocalc.Point;
import com.softserveinc.ch067.easypay.model.Address;

public class GeoUtil {
    public static Double getDistance(Address address1, Address address2) {
        return EarthCalc.getDistance(
                new Point(
                        new DegreeCoordinate(address1.getLat()),
                        new DegreeCoordinate(address1.getLng())
                ),
                new Point(
                        new DegreeCoordinate(address2.getLat()),
                        new DegreeCoordinate(address2.getLng())
                )
        );
    }
}
