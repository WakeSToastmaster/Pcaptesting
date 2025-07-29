#include "approx.h"
#include <cmath>
#include <iostream>

namespace approx {

    Eigen::MatrixXd build_A_matrix() {
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0 };
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
        //  Применяем логарифм к y_values
        std::vector<double> ln_y_values;
        for (double y : y_values) {
            if (y <= 0) {
                // Обработка неположительных значений
                ln_y_values.push_back(std::log(y + 1e-10));
            }
            else {
                ln_y_values.push_back(std::log(y));
            }
        }
        Eigen::MatrixXd A = build_A_matrix();  
        Eigen::VectorXd b = build_b_vector(ln_y_values);  // Передаем ln(y) вместо y

        //  Решаем систему
        Eigen::VectorXd quad_coeffs = A.colPivHouseholderQr().solve(b);

        // Преобразуем коэффициенты квадратичной функции в параметры гаусса
        double a = quad_coeffs[2];  // Коэффициент при x^2
        double b_coeff = quad_coeffs[1];  // Коэффициент при x
        double c = quad_coeffs[0];  // Свободный член

        double sigma = std::sqrt(-1.0 / (2.0 * a));
        double mu = b_coeff * sigma * sigma;
        double A_gauss = std::exp(c + (mu * mu) / (2 * sigma * sigma));

        Eigen::VectorXd gaussian_params(3);
        gaussian_params << A_gauss, mu, sigma;
        return gaussian_params;
    }

    double calculate_mse(const std::vector<std::vector<double>>& data, const Eigen::VectorXd& coeffs) {
        double total_error = 0.0;
        int total_points = 0;
        const std::vector<double> x_points = { 1.0, 2.0, 3.0, 4.0, 5.0 };

        for (const auto& ex : data) {
            for (size_t i = 0; i < 5; ++i) {
                double x = x_points[i];
                double y_actual = ex[i];
                double y_predicted = coeffs[0] * std::exp(-std::pow(x - coeffs[1], 2) / (2 * std::pow(coeffs[2], 2)));
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
                double y_predicted = coeffs[0] * std::exp(-std::pow(x - coeffs[1], 2) / (2 * std::pow(coeffs[2], 2)));
                total_percentage += std::abs(y_actual - y_predicted) / y_actual * 100.0;
                total_points++;
            }
        }
        return total_percentage / total_points;
    }

    void print_coefficients(const Eigen::VectorXd& coeffs) {
        std::cout << "A (amplitude): " << coeffs[0] << "\n";
        std::cout << "m (center):    " << coeffs[1] << "\n";
        std::cout << "o (width):     " << coeffs[2] << "\n";
    }

}