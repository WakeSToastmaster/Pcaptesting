#include <Eigen/Dense>

class KalmanFilter {
public:
    KalmanFilter(int state_dim, int meas_dim);

    void init(const Eigen::VectorXd& initial_state,
        const Eigen::MatrixXd& initial_covariance);

    void predict(const Eigen::MatrixXd& F, const Eigen::MatrixXd& Q);
    void update(const Eigen::VectorXd& z,
        const Eigen::MatrixXd& H,
        const Eigen::MatrixXd& R);

    Eigen::VectorXd getState() const { return x; }
    Eigen::MatrixXd getCovariance() const { return P; }

private:
    int state_dim;
    int meas_dim;

    Eigen::VectorXd x;  // State estimate
    Eigen::MatrixXd P;  // Estimate covariance
    Eigen::MatrixXd I;  // Identity matrix
};