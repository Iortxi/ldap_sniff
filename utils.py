
import sys
from typing import Literal, NoReturn


def soltar_error(mensaje: str, codigo: int) -> NoReturn:
    """
    Finaliza la ejecucion del programa con un mensaje de error y un codigo de salida.

    Args:
        mensaje: Cadena de texto con el mensaje de error a escribir por salida estándar.
        codigo: Entero con el código de salida con el que finalizar la ejecución.
    """

    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)


def recoger_opcion(mostrar_menu: bool) -> Literal[0, 1]:
    """
    La ejecución queda a la espera de que el usuario ejecute una opcion. Opcionalmente muestra menu de opciones.

    Args:
        mostrar_menu: Booleano para mostrar o no el menú de opciones disponibles por salida estándar.

    Returns:
        int: Entero con la opción escogida por el usuario (0 | 1).
    """

    # Menu de opciones
    if mostrar_menu:
        print('\n------------------ OPTIONS ------------------')
        print('[0] Collect remote capture and keep capturing')
        print('[1] Collect remote capture and stop capturing\n')

    # Espera
    input_ = input('\n[?] Select an option (0 or 1): ')

    # Bucle infinito hasta obtener un resultado valido
    while True:
        try:
            opcion = int(input_)
            if opcion != 0 and opcion != 1:
                raise ValueError
            break
        except ValueError:
            input_ = input('\n[!] Give a valid option (0 or 1): ')

    return opcion
