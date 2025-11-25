
import sys


def soltar_error(mensaje: str, codigo: int):
    """ Finaliza la ejecucion del programa con un mensaje de error y un codigo de salida """

    print(f'\n[!] {mensaje}\n')
    sys.exit(codigo)


def recoger_opcion(mostrar_menu: bool):
    """ Queda a la espera de que el usuario ejecute una opcion. Opcionalmente muestra menu de opciones """

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

