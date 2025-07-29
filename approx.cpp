#include "approx.h"
#include <cmath>
#include <iostream>

namespace approx {

    Eigen::MatrixXd build_A_matrix() {
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0};
        Eigen::MatrixXd A(3, 3);

        for (int row = 0; row < 3; ++row) {
            for (int col = 0; col < 3; ++col) {
                double sum = 0.0;
                int power = row + col;
                for (double x : x_points) {
                    sum += std::pow(x, power);
                }
                A(row, col) = sum;
            }
        }
        return A;
    }

    Eigen::VectorXd build_b_vector(const std::vector<double>& y_values) {
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0 };
        Eigen::VectorXd b(3);

        for (int i = 0; i < 3; ++i) {
            double sum = 0.0;
            for (size_t j = 0; j < y_values.size(); ++j) {
                sum += y_values[j] * std::pow(x_points[j], i);
            }
            b(i) = sum;
        }
        return b;
    }

    Eigen::VectorXd solve_system(const std::vector<double>& y_values) {
        static const Eigen::MatrixXd A = build_A_matrix();
        Eigen::VectorXd b = build_b_vector(y_values);
        return A.colPivHouseholderQr().solve(b);
    }

    double calculate_mse(const std::vector<std::vector<double>>& data, const Eigen::VectorXd& coeffs) {
        double total_error = 0.0;
        int total_points = 0;
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0 };

        for (const auto& ex : data) {
            for (size_t i = 0; i < 5; ++i) {
                double x = x_points[i];
                double y_actual = ex[i];
                double y_predicted = coeffs[0] + coeffs[1] * x + coeffs[2] * x * x;
                total_error += std::pow(y_actual - y_predicted, 2);
                total_points++;
            }
        }
        return total_error / total_points;
    }

    double calculate_mean_percentage_error(const std::vector<std::vector<double>>& data, const Eigen::VectorXd& coeffs) {
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0 };
        double total_percentage = 0.0;
        int total_points = 0;

        for (const auto& ex : data) {
            for (size_t i = 0; i < 5; ++i) {
                double x = x_points[i];
                double y_actual = ex[i];
                if (y_actual == 0) continue;
                double y_predicted = coeffs[0] + coeffs[1] * x + coeffs[2] * x * x;
                total_percentage += std::abs(y_actual - y_predicted) / y_actual * 100.0;
                total_points++;
            }
        }
        return total_percentage / total_points;
    }

    void print_coefficients(const Eigen::VectorXd& coeffs) {
        std::cout << "a0 (const): " << coeffs[0] << "\n";
        std::cout << "a1 (x):     " << coeffs[1] << "\n";
        std::cout << "a2 (x^2):   " << coeffs[2] << "\n";
    }

}