package com.shubham.project.uber.uberApp.services;

import com.shubham.project.uber.uberApp.entities.RideRequest;

public interface RideRequestService {

    RideRequest findRideRequestById(Long rideRequestId);

    void update(RideRequest rideRequest);
}
