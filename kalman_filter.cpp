#include "kalman_filter.h"
#include <iostream>

KalmanFilter::KalmanFilter(int state_dim, int meas_dim) : state_dim(state_dim), meas_dim(meas_dim) {
    x = Eigen::VectorXd::Zero(state_dim);
    P = Eigen::MatrixXd::Identity(state_dim, state_dim);
    I = Eigen::MatrixXd::Identity(state_dim, state_dim);
}

void KalmanFilter::init(const Eigen::VectorXd& initial_state, const Eigen::MatrixXd& initial_covariance) {
    x = initial_state;
    P = initial_covariance;
}

void KalmanFilter::predict(const Eigen::MatrixXd& F, const Eigen::MatrixXd& Q) {
    x = F * x;
    P = F * P * F.transpose() + Q;
}

void KalmanFilter::update(const Eigen::VectorXd& z, const Eigen::MatrixXd& H, const Eigen::MatrixXd& R) {
    Eigen::VectorXd y = z - H * x;
    Eigen::MatrixXd S = H * P * H.transpose() + R;
    Eigen::MatrixXd K = P * H.transpose() * S.inverse();

    x = x + K * y;
    P = (I - K * H) * P;
}