package com.shubham.project.uber.uberApp.strategies;

import com.shubham.project.uber.uberApp.entities.Driver;
import com.shubham.project.uber.uberApp.entities.RideRequest;

import java.util.List;

public interface DriverMatchingStrategy {

    List<Driver> findMatchingDriver(RideRequest rideRequest);
}
