#pragma once
#include <vector>
#include <Eigen/Dense>

namespace approx {

    // Структура для хранения коэффициентов параболы
    struct ParabolaCoeffs {
        double a0; // Константа
        double a1; // Коэффициент при x
        double a2; // Коэффициент при x^2
    };

    // Функция для построения матрицы A
    Eigen::MatrixXd build_A_matrix();

    // Функция для построения вектора b
    Eigen::VectorXd build_b_vector(const std::vector<double>& y_values);

    // Решение системы уравнений для нахождения коэффициентов параболы
    Eigen::VectorXd solve_system(const std::vector<double>& y_values);

    // Вычисление среднеквадратичной ошибки (MSE)
    double calculate_mse(const std::vector<std::vector<double>>& data, const Eigen::VectorXd& coeffs);

    // Вычисление средней процентной ошибки (MPE)
    double calculate_mean_percentage_error(const std::vector<std::vector<double>>& data, const Eigen::VectorXd& coeffs);

    // Вывод коэффициентов в консоль
    void print_coefficients(const Eigen::VectorXd& coeffs);

} // namespace approx