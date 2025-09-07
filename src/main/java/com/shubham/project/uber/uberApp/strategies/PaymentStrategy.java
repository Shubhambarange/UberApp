package com.shubham.project.uber.uberApp.strategies;

import com.shubham.project.uber.uberApp.entities.Payment;

public interface PaymentStrategy {
    Double PLATFORM_COMMISSION = 0.3;
    void processPayment(Payment payment);

}
