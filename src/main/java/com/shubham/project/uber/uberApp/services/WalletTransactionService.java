package com.shubham.project.uber.uberApp.services;

import com.shubham.project.uber.uberApp.dto.WalletTransactionDto;
import com.shubham.project.uber.uberApp.entities.WalletTransaction;

public interface WalletTransactionService {

    void createNewWalletTransaction(WalletTransaction walletTransaction);

}
